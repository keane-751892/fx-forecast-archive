(function (scope) {
  "use strict";

  const STATUS_LABELS = Object.freeze({
    sealed: "已封存",
    timestamp_pending: "等待时间证明",
    verified: "事前存档已核验",
    review_pending: "期限已结束待人工复核",
    revealed: "已揭示",
    reviewed: "已复盘",
    receipt_invalid: "事前证明失效"
  });
  const VERIFY_OK = "事前记录核验通过，复盘结果通过一致性检查";
  const VERIFY_FAILED = "核验失败，本记录不可采用";
  const SCHEMA_VERSION = "forecast-envelope-v1";
  const ENCRYPTION_ALGORITHM = "AES-256-GCM";
  const COMMITMENT_ALGORITHM = "SHA-256";
  const COMMITMENT_INPUT = "salt||payload_canonical_utf8";
  const MANIFEST_FIELDS = [
    "archive_id", "commitment_algorithm", "commitment_hash",
    "commitment_input", "encryption_algorithm", "level",
    "previous_commitment_hash", "schema_version"
  ];
  const ENVELOPE_FIELDS = [
    "aad", "ciphertext_b64", "encryption_algorithm", "nonce_b64", "schema_version"
  ];
  const SALT_FIELD = ["salt", "b64"].join("_");
  const KEY_FIELD = ["key", "b64"].join("_");
  const REVEAL_FIELDS = [
    "approved_at", "archive_id", KEY_FIELD, "level",
    "payload_canonical", "result_snapshot", "result_snapshot_hash", SALT_FIELD
  ];
  const RESULT_DOCUMENT_FIELDS = [
    "archive_id", "level", "result_snapshot", "result_snapshot_hash"
  ];
  const RESULT_FIELDS = ["base_rate", "t0", "t1"];
  const HORIZON_RESULT_FIELDS = [
    "actual_direction", "actual_rate", "direction_comparison", "in_range"
  ];
  const BASE_PAYLOAD_FIELDS = [
    "archive_id", "data_watermark", "forecast_generated_at",
    "forecast_version", "horizon_end", "judgments", "level",
    "schema_version", "trade_date"
  ];
  const DIRECTIONS = new Set([
    ["人民币", "偏升"].join(""),
    ["人民币", "偏贬"].join(""),
    "震荡"
  ]);
  const PADDED_LENGTHS = Object.freeze({ L1: 1024, L2: 1536 });
  const encoder = new TextEncoder();
  const decoder = new TextDecoder("utf-8", { fatal: true });

  function exactKeys(value, expected) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return false;
    const actual = Object.keys(value).sort();
    const wanted = expected.slice().sort();
    return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
  }

  function safeText(value, maximum) {
    return typeof value === "string" && value.trim().length > 0 &&
      value.length <= maximum && !/\p{C}/u.test(value);
  }

  function validHash(value) {
    return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
  }

  function safeGitHubReceiptUrl(value) {
    if (typeof value !== "string") return null;
    return /^https:\/\/github\.com\/keane-751892\/fx-forecast-archive\/actions\/runs\/[1-9][0-9]*$/.test(value)
      ? value
      : null;
  }

  function validDate(value) {
    if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
    const parsed = new Date(`${value}T00:00:00Z`);
    return !Number.isNaN(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value;
  }

  function validDateTime(value) {
    if (!safeText(value, 64)) return false;
    if (validDate(value)) return true;
    if (!/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:\d{2})?$/.test(value)) {
      return false;
    }
    return !Number.isNaN(new Date(value.replace(" ", "T")).getTime());
  }

  function bytesFromBase64(value) {
    if (typeof value !== "string" || value.length === 0) throw new Error("invalid base64");
    let binary;
    if (typeof atob === "function") binary = atob(value);
    else binary = Buffer.from(value, "base64").toString("binary");
    const bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
    const canonical = typeof btoa === "function"
      ? btoa(binary)
      : Buffer.from(bytes).toString("base64");
    if (canonical !== value) throw new Error("non-canonical base64");
    return bytes;
  }

  function hex(bytes) {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
  }

  function joinBytes(first, second) {
    const joined = new Uint8Array(first.length + second.length);
    joined.set(first, 0);
    joined.set(second, first.length);
    return joined;
  }

  function canonicalJson(value) {
    if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
    if (value && typeof value === "object") {
      return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
    }
    return JSON.stringify(value);
  }

  function pythonFloat(value) {
    if (typeof value !== "number" || !Number.isFinite(value)) throw new Error("invalid number");
    const absolute = Math.abs(value);
    const exponent = absolute === 0 ? 0 : Math.floor(Math.log10(absolute));
    let text;
    if (absolute !== 0 && (exponent < -4 || exponent >= 16)) {
      text = value.toExponential();
    } else {
      text = String(value);
      if (Number.isInteger(value)) text += ".0";
    }
    return text.replace(/e([+-]?)(\d)$/i, "e$10$2");
  }

  function canonicalPayloadJson(value, path) {
    const currentPath = path || [];
    if (Array.isArray(value)) {
      return `[${value.map((item, index) => canonicalPayloadJson(item, currentPath.concat(index))).join(",")}]`;
    }
    if (value && typeof value === "object") {
      return `{${Object.keys(value).sort().map(key =>
        `${JSON.stringify(key)}:${canonicalPayloadJson(value[key], currentPath.concat(key))}`
      ).join(",")}}`;
    }
    if (typeof value === "number") {
      const finalKey = currentPath[currentPath.length - 1];
      return finalKey === "low" || finalKey === "high" ? pythonFloat(value) : JSON.stringify(value);
    }
    return JSON.stringify(value);
  }

  function canonicalResultJson(value, path) {
    const currentPath = path || [];
    if (Array.isArray(value)) {
      return `[${value.map((item, index) => canonicalResultJson(item, currentPath.concat(index))).join(",")}]`;
    }
    if (value && typeof value === "object") {
      return `{${Object.keys(value).sort().map(key =>
        `${JSON.stringify(key)}:${canonicalResultJson(value[key], currentPath.concat(key))}`
      ).join(",")}}`;
    }
    if (typeof value === "number") {
      const finalKey = currentPath[currentPath.length - 1];
      return finalKey === "base_rate" || finalKey === "actual_rate"
        ? pythonFloat(value)
        : JSON.stringify(value);
    }
    return JSON.stringify(value);
  }

  function validateHorizonItems(items, valueFields) {
    if (!Array.isArray(items) || items.length !== 2) return false;
    return items.every((item, index) => {
      if (!exactKeys(item, ["horizon"].concat(valueFields))) return false;
      return item.horizon === (index === 0 ? "T+0" : "T+1");
    });
  }

  function validatePayload(payload, payloadText, manifest) {
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) return false;
    if (payload.level !== "L1" && payload.level !== "L2") return false;
    const fields = payload.level === "L2"
      ? BASE_PAYLOAD_FIELDS.concat("ranges")
      : BASE_PAYLOAD_FIELDS;
    if (!exactKeys(payload, fields)) return false;
    if (
      payload.schema_version !== SCHEMA_VERSION ||
      payload.archive_id !== manifest.archive_id ||
      payload.level !== manifest.level ||
      !/^FX-[0-9]{6,}-R[0-9]{2,}$/.test(payload.archive_id) ||
      !validDate(payload.trade_date) ||
      !validDateTime(payload.forecast_generated_at) ||
      !validDateTime(payload.horizon_end) ||
      !validDateTime(payload.data_watermark) ||
      !safeText(payload.forecast_version, 128)
    ) return false;
    if (!validateHorizonItems(payload.judgments, ["direction"])) return false;
    if (payload.judgments.some(item => !DIRECTIONS.has(item.direction))) return false;
    if (payload.level === "L2") {
      if (!validateHorizonItems(payload.ranges, ["high", "low"])) return false;
      if (payload.ranges.some(item =>
        typeof item.low !== "number" || typeof item.high !== "number" ||
        !Number.isFinite(item.low) || !Number.isFinite(item.high) ||
        item.low <= 0 || item.high <= 0 ||
        item.low > item.high
      )) return false;
    }
    return canonicalPayloadJson(payload) === payloadText;
  }

  function positiveNumber(value) {
    return typeof value === "number" && Number.isFinite(value) && value > 0;
  }

  function actualDirection(baseRate, actualRate) {
    if (actualRate < baseRate) return ["人民币", "偏升"].join("");
    if (actualRate > baseRate) return ["人民币", "偏贬"].join("");
    return "震荡";
  }

  function directionComparison(direction, baseRate, actualRate) {
    if (direction === "震荡" && Math.abs(actualRate - baseRate) / baseRate < 0.001) {
      return 1;
    }
    return actualDirection(baseRate, actualRate) === direction ? 1 : 0;
  }

  function validateResultSnapshot(result, payload) {
    if (!exactKeys(result, RESULT_FIELDS) || !positiveNumber(result.base_rate)) return false;
    const judgmentByHorizon = new Map(
      payload.judgments.map(item => [item.horizon, item.direction])
    );
    const rangeByHorizon = payload.level === "L2"
      ? new Map(payload.ranges.map(item => [item.horizon, item]))
      : null;
    return [["t0", "T+0"], ["t1", "T+1"]].every(([key, horizon]) => {
      const item = result[key];
      if (!exactKeys(item, HORIZON_RESULT_FIELDS)) return false;
      if (
        !positiveNumber(item.actual_rate) ||
        !DIRECTIONS.has(item.actual_direction) ||
        !Number.isInteger(item.direction_comparison) ||
        ![0, 1].includes(item.direction_comparison) ||
        !Number.isInteger(item.in_range) ||
        ![0, 1].includes(item.in_range)
      ) return false;
      if (item.actual_direction !== actualDirection(result.base_rate, item.actual_rate)) {
        return false;
      }
      if (
        item.direction_comparison !== directionComparison(
          judgmentByHorizon.get(horizon), result.base_rate, item.actual_rate
        )
      ) return false;
      if (rangeByHorizon) {
        const range = rangeByHorizon.get(horizon);
        const expected = range.low <= item.actual_rate && item.actual_rate <= range.high ? 1 : 0;
        if (item.in_range !== expected) return false;
      }
      return true;
    });
  }

  function webCrypto() {
    if (scope.crypto && scope.crypto.subtle) return scope.crypto;
    if (typeof require === "function") return require("node:crypto").webcrypto;
    throw new Error("web crypto unavailable");
  }

  async function verifyForecastRecord(manifest, envelope, reveal, resultDocument) {
    try {
      if (
        !exactKeys(manifest, MANIFEST_FIELDS) ||
        !exactKeys(envelope, ENVELOPE_FIELDS) ||
        !exactKeys(reveal, REVEAL_FIELDS) ||
        !exactKeys(resultDocument, RESULT_DOCUMENT_FIELDS)
      ) throw new Error("invalid evidence structure");
      if (
        manifest.schema_version !== SCHEMA_VERSION ||
        envelope.schema_version !== SCHEMA_VERSION ||
        manifest.encryption_algorithm !== ENCRYPTION_ALGORITHM ||
        envelope.encryption_algorithm !== ENCRYPTION_ALGORITHM ||
        manifest.commitment_algorithm !== COMMITMENT_ALGORITHM ||
        manifest.commitment_input !== COMMITMENT_INPUT ||
        (manifest.level !== "L1" && manifest.level !== "L2") ||
        !/^FX-[0-9]{6,}-R[0-9]{2,}$/.test(manifest.archive_id) ||
        !validHash(manifest.commitment_hash) ||
        !(manifest.previous_commitment_hash === null || validHash(manifest.previous_commitment_hash)) ||
        reveal.archive_id !== manifest.archive_id ||
        reveal.level !== manifest.level ||
        resultDocument.archive_id !== manifest.archive_id ||
        resultDocument.level !== manifest.level ||
        !validHash(reveal.result_snapshot_hash) ||
        resultDocument.result_snapshot_hash !== reveal.result_snapshot_hash ||
        !validDateTime(reveal.approved_at)
      ) throw new Error("unsupported evidence");
      const payloadText = reveal.payload_canonical;
      if (typeof payloadText !== "string" || payloadText.length === 0) throw new Error("missing payload");
      const salt = bytesFromBase64(reveal[SALT_FIELD]);
      const keyBytes = bytesFromBase64(reveal[KEY_FIELD]);
      const nonce = bytesFromBase64(envelope.nonce_b64);
      const ciphertext = bytesFromBase64(envelope.ciphertext_b64);
      if (salt.length !== 32 || keyBytes.length !== 32 || nonce.length !== 12) {
        throw new Error("invalid evidence length");
      }
      const paddedLength = PADDED_LENGTHS[manifest.level];
      if (ciphertext.length !== paddedLength + 16) throw new Error("invalid ciphertext length");
      const expectedAad = `${SCHEMA_VERSION}:${manifest.archive_id}:${manifest.level}`;
      if (envelope.aad !== expectedAad) throw new Error("invalid aad");
      const payloadBytes = encoder.encode(payloadText);
      const digest = await webCrypto().subtle.digest("SHA-256", joinBytes(salt, payloadBytes));
      if (hex(new Uint8Array(digest)) !== manifest.commitment_hash) throw new Error("fingerprint mismatch");

      const key = await webCrypto().subtle.importKey(
        "raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]
      );
      const plaintext = new Uint8Array(await webCrypto().subtle.decrypt(
        {
          name: "AES-GCM",
          iv: nonce,
          additionalData: encoder.encode(envelope.aad),
          tagLength: 128
        },
        key,
        ciphertext
      ));
      if (plaintext.length !== paddedLength) throw new Error("invalid plaintext");
      const bodyLength = new DataView(plaintext.buffer, plaintext.byteOffset, 4).getUint32(0, false);
      if (bodyLength <= 0 || bodyLength > plaintext.length - 4) throw new Error("invalid plaintext length");
      const wrapperText = decoder.decode(plaintext.slice(4, 4 + bodyLength));
      const wrapper = JSON.parse(wrapperText);
      if (canonicalJson(wrapper) !== wrapperText) throw new Error("non-canonical wrapper");
      if (Object.keys(wrapper).sort().join(",") !== "payload_canonical,previous_commitment_hash") {
        throw new Error("invalid wrapper");
      }
      if (wrapper.previous_commitment_hash !== manifest.previous_commitment_hash) throw new Error("chain mismatch");
      if (wrapper.payload_canonical !== payloadText) throw new Error("decrypted content mismatch");
      const payload = JSON.parse(payloadText);
      if (!validatePayload(payload, payloadText, manifest)) throw new Error("invalid payload");
      const revealResult = reveal.result_snapshot;
      const publicResult = resultDocument.result_snapshot;
      if (
        canonicalResultJson(revealResult) !== canonicalResultJson(publicResult) ||
        !validateResultSnapshot(revealResult, payload)
      ) throw new Error("invalid result snapshot");
      const resultBytes = encoder.encode(canonicalResultJson(revealResult));
      const resultDigest = await webCrypto().subtle.digest("SHA-256", resultBytes);
      if (hex(new Uint8Array(resultDigest)) !== reveal.result_snapshot_hash) {
        throw new Error("result fingerprint mismatch");
      }
      return {
        ok: true,
        message: VERIFY_OK,
        payload: payload,
        result: reveal.result_snapshot
      };
    } catch (_) {
      return { ok: false, message: VERIFY_FAILED };
    }
  }

  function text(element, value) {
    element.textContent = value == null ? "—" : String(value);
    return element;
  }

  function formatTime(value) {
    if (!value) return "—";
    const instant = new Date(value);
    if (Number.isNaN(instant.getTime())) return String(value).replace("T", " ");
    return new Intl.DateTimeFormat("zh-CN", {
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", hour12: false
    }).format(instant);
  }

  function detailItem(label, value) {
    const wrapper = document.createElement("div");
    wrapper.className = "detail-item";
    text(wrapper.appendChild(document.createElement("dt")), label);
    text(wrapper.appendChild(document.createElement("dd")), value);
    return wrapper;
  }

  function technicalDetails(record) {
    const details = document.createElement("details");
    details.className = "technical-details";
    text(details.appendChild(document.createElement("summary")), "验证详情");
    const body = details.appendChild(document.createElement("div"));
    body.className = "technical-body";
    const list = body.appendChild(document.createElement("dl"));
    list.appendChild(detailItem("公开版本", `${record.archive_id} / ${record.level}`));
    list.appendChild(detailItem("时间证明", record.ots_status === "CONFIRMED" ? "已确认" : "等待确认"));
    list.appendChild(detailItem("事前记录核验", "SHA-256 指纹与 AES-GCM 密封信封交叉核对"));
    list.appendChild(detailItem(
      "复盘结果核验",
      "复盘结果不属于事前密封内容；公开时另做存档哈希与双文件一致性检查"
    ));
    const receiptUrl = safeGitHubReceiptUrl(record.github_receipt_url);
    if (receiptUrl) {
      const link = body.appendChild(document.createElement("a"));
      link.className = "evidence-link";
      link.href = receiptUrl;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.textContent = "查看 GitHub 服务器收件记录";
    }
    return details;
  }

  function comparisonView(payload, result) {
    return payload.judgments.map(item => {
      const horizonKey = item.horizon === "T+0" ? "t0" : "t1";
      const actual = result[horizonKey];
      const row = {
        horizon: item.horizon,
        judgment: `事前记录：${item.direction}`,
        actual: `实际结果：${actual.actual_rate}（${actual.actual_direction}）`,
        comparison: actual.direction_comparison === 1 ? "方向一致" : "方向偏离"
      };
      if (payload.level === "L2") {
        const range = payload.ranges.find(candidate => candidate.horizon === item.horizon);
        row.range = `事前区间：${range.low}—${range.high}`;
        row.rangeResult = actual.in_range === 1
          ? "实际价格落在区间内"
          : "实际价格超出区间";
      }
      return row;
    });
  }

  function judgmentRows(payload, result) {
    const section = document.createElement("div");
    section.className = "opened-record";
    const title = section.appendChild(document.createElement("h4"));
    title.textContent = "事前记录与实际结果";
    comparisonView(payload, result).forEach(item => {
      const row = section.appendChild(document.createElement("div"));
      row.className = "comparison-row";
      text(row.appendChild(document.createElement("strong")), item.horizon);
      text(row.appendChild(document.createElement("span")), item.judgment);
      text(row.appendChild(document.createElement("span")), item.actual);
      text(row.appendChild(document.createElement("span")), item.comparison);
      if (item.range) {
        text(row.appendChild(document.createElement("span")), item.range);
        text(row.appendChild(document.createElement("span")), item.rangeResult);
      }
    });
    return section;
  }

  async function openRecord(record, container, button) {
    button.disabled = true;
    button.textContent = "正在核对……";
    try {
      const [manifestResponse, envelopeResponse, revealResponse, resultResponse] = await Promise.all([
        fetch(record.manifest_url), fetch(record.envelope_url),
        fetch(record.reveal_url), fetch(record.result_url)
      ]);
      if (!manifestResponse.ok || !envelopeResponse.ok || !revealResponse.ok || !resultResponse.ok) {
        throw new Error("load failed");
      }
      const [manifest, envelope, reveal, resultDocument] = await Promise.all([
        manifestResponse.json(), envelopeResponse.json(),
        revealResponse.json(), resultResponse.json()
      ]);
      const verification = await verifyForecastRecord(
        manifest, envelope, reveal, resultDocument
      );
      const note = container.appendChild(document.createElement("p"));
      note.className = verification.ok ? "verification-note" : "verification-note verification-failed";
      note.textContent = verification.message;
      if (verification.ok) {
        container.appendChild(judgmentRows(verification.payload, verification.result));
        button.remove();
      } else {
        button.textContent = "重新核验";
        button.disabled = false;
      }
    } catch (_) {
      const note = container.appendChild(document.createElement("p"));
      note.className = "verification-note verification-failed";
      note.textContent = VERIFY_FAILED;
      button.textContent = "重新核验";
      button.disabled = false;
    }
  }

  function recordCard(record) {
    const article = document.createElement("article");
    article.className = "record-card";
    const head = article.appendChild(document.createElement("div"));
    head.className = "record-head";
    const identity = head.appendChild(document.createElement("div"));
    text(identity.appendChild(document.createElement("p")), `${record.archive_id} · ${record.record_kind || "历史记录"}`).className = "record-number";
    text(identity.appendChild(document.createElement("h3")), record.trade_date);
    const status = text(head.appendChild(document.createElement("span")), STATUS_LABELS[record.state] || record.state_label);
    status.className = record.state === "receipt_invalid" ? "status-stamp status-stamp-invalid" : "status-stamp";

    const facts = article.appendChild(document.createElement("dl"));
    facts.className = "record-facts";
    facts.appendChild(detailItem("封存时间", formatTime(record.sealed_at)));
    facts.appendChild(detailItem("判断期限", record.judgment_horizon));
    facts.appendChild(detailItem("计划揭示时间", record.planned_reveal_at));
    if (record.missing_before && record.missing_before.length) {
      facts.appendChild(detailItem("编号连续性", `此前缺少 ${record.missing_before.join("、")} 号`));
    }
    if (record.revision_summary) facts.appendChild(detailItem("本次修订", record.revision_summary));

    if (record.reveal_url) {
      const openArea = article.appendChild(document.createElement("div"));
      openArea.className = "open-area";
      const button = openArea.appendChild(document.createElement("button"));
      button.type = "button";
      button.className = "open-button";
      button.textContent = "打开原始密封记录";
      button.addEventListener("click", () => openRecord(record, openArea, button));
    } else if (record.state === "receipt_invalid") {
      const lock = article.appendChild(document.createElement("p"));
      lock.className = "lock-note lock-note-invalid";
      lock.textContent = record.invalidation_note
        || "本记录的事前公开证明已失效，永久不可用于公开复盘，仅保留编号与密封文件。";
    } else {
      const lock = article.appendChild(document.createElement("p"));
      lock.className = "lock-note";
      lock.textContent = record.state === "review_pending"
        ? "期限已经结束，原记录仍需人工复核后才会公开。"
        : "原记录仍在密封中，到期前不展示判断内容。";
    }
    article.appendChild(technicalDetails(record));
    return article;
  }

  function renderSummary(summary) {
    const grid = document.getElementById("summary-grid");
    grid.replaceChildren();
    const items = [
      ["累计记录", summary.total_records],
      ["连续记录", summary.continuous_records],
      ["缺少编号", summary.missing_count],
      ["已经揭示", summary.revealed_records]
    ];
    if (typeof summary.invalidated_records === "number" && summary.invalidated_records > 0) {
      items.push(["证明失效", summary.invalidated_records]);
    }
    items.forEach(([label, value]) => grid.appendChild(detailItem(label, value)));
  }

  async function start() {
    const list = document.getElementById("record-list");
    try {
      const [recordsResponse, summaryResponse] = await Promise.all([
        fetch("data/records.json"), fetch("data/summary.json")
      ]);
      if (!recordsResponse.ok || !summaryResponse.ok) throw new Error("load failed");
      const [records, summary] = await Promise.all([recordsResponse.json(), summaryResponse.json()]);
      renderSummary(summary);
      list.replaceChildren();
      if (!records.length) {
        text(list.appendChild(document.createElement("p")), "暂无公开存档。").className = "loading";
        return;
      }
      records.slice().reverse().forEach(record => list.appendChild(recordCard(record)));
    } catch (_) {
      list.replaceChildren();
      text(list.appendChild(document.createElement("p")), "存档暂时无法读取，请稍后再试。").className = "loading";
    }
  }

  const exported = {
    comparisonView, safeGitHubReceiptUrl, verifyForecastRecord, STATUS_LABELS
  };
  if (typeof module !== "undefined" && module.exports) module.exports = exported;
  scope.ForecastLedger = exported;
  if (typeof document !== "undefined") document.addEventListener("DOMContentLoaded", start);
})(typeof globalThis !== "undefined" ? globalThis : this);
