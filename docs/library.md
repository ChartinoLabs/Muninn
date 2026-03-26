# Parser Library

Browse all parsers available in Muninn. Use the search box and filters to find parsers by command, OS, or feature tag. Click any row to view its schema and example output.

<div id="parser-catalog">
  <div class="catalog-controls">
    <select id="catalog-version">
      <option value="">Loading versions...</option>
    </select>
    <input type="text" id="catalog-search" placeholder="Search by command..." />
    <select id="catalog-os-filter">
      <option value="">All Platforms</option>
    </select>
    <select id="catalog-tag-filter">
      <option value="">All Tags</option>
    </select>
  </div>

  <div id="catalog-stats"></div>

  <table id="catalog-table">
    <thead>
      <tr>
        <th class="expand-col"></th>
        <th data-sort="os">Platform</th>
        <th data-sort="command">Command</th>
        <th data-sort="tags">Tags</th>
      </tr>
    </thead>
    <tbody id="catalog-body">
    </tbody>
  </table>

  <div id="catalog-empty" style="display: none;">
    No parsers match your filters.
  </div>
</div>

<style>
  .md-sidebar--secondary {
    display: none;
  }
  .md-main__inner.md-grid {
    max-width: none;
  }
  .catalog-controls {
    display: flex;
    gap: 0.75rem;
    margin-bottom: 1rem;
    flex-wrap: wrap;
  }
  #catalog-search {
    flex: 1;
    min-width: 200px;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
    font-size: 0.9rem;
  }
  #catalog-search:focus {
    outline: 2px solid var(--md-accent-fg-color);
    border-color: transparent;
  }
  .catalog-controls select {
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color);
    font-size: 0.9rem;
    min-width: 150px;
  }
  #catalog-stats {
    margin-bottom: 1rem;
    font-size: 0.85rem;
    color: var(--md-default-fg-color--light);
  }
  #catalog-table {
    width: 100%;
    border-collapse: collapse;
    table-layout: fixed;
  }
  #catalog-table th {
    cursor: pointer;
    user-select: none;
    white-space: nowrap;
    padding: 0.6rem 0.75rem;
    text-align: left;
    border-bottom: 2px solid var(--md-default-fg-color--lighter);
  }
  #catalog-table th:hover {
    color: var(--md-accent-fg-color);
  }
  #catalog-table th::after {
    content: " \2195";
    font-size: 0.75em;
    opacity: 0.4;
  }
  #catalog-table th.sort-asc::after {
    content: " \2191";
    opacity: 1;
  }
  #catalog-table th.sort-desc::after {
    content: " \2193";
    opacity: 1;
  }
  #catalog-table td {
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
    vertical-align: top;
  }
  th.expand-col {
    width: 2rem;
    cursor: default;
  }
  th.expand-col::after {
    content: none;
  }
  td.expand-cell {
    width: 2rem;
    text-align: center;
    color: var(--md-default-fg-color--lighter);
    font-size: 0.7rem;
  }
  td.expand-cell span {
    display: inline-block;
    transition: transform 0.2s ease;
  }
  tr.catalog-row.expanded td.expand-cell span {
    transform: rotate(90deg);
  }
  tr.catalog-row {
    cursor: pointer;
  }
  tr.catalog-row:hover td {
    background: var(--md-code-bg-color);
  }
  tr.catalog-row:hover td.expand-cell {
    color: var(--md-accent-fg-color);
  }
  tr.catalog-row.expanded td {
    background: var(--md-code-bg-color);
    border-bottom: none;
  }
  tr.catalog-row.expanded td.expand-cell {
    color: var(--md-accent-fg-color);
  }
  .tag-chip {
    display: inline-block;
    padding: 0.1rem 0.5rem;
    margin: 0.1rem 0.15rem;
    border-radius: 12px;
    font-size: 0.75rem;
    background: var(--md-accent-fg-color--transparent);
    color: var(--md-accent-fg-color);
    border: 1px solid var(--md-accent-fg-color);
    white-space: nowrap;
  }
  .command-text {
    font-family: var(--md-code-font);
    font-size: 0.85rem;
  }
  #catalog-empty {
    padding: 2rem;
    text-align: center;
    color: var(--md-default-fg-color--light);
  }

  /* Detail panel */
  tr.detail-row td {
    padding: 0;
    border-bottom: 1px solid var(--md-default-fg-color--lightest);
  }
  .detail-panel {
    padding: 1rem 1.5rem 1.5rem;
    background: var(--md-code-bg-color);
    overflow: hidden;
    min-width: 0;
  }
  .detail-panel h4 {
    margin: 0 0 0.5rem;
    font-size: 0.95rem;
    color: var(--md-default-fg-color);
  }

  /* Schema tree */
  .schema-tree {
    font-family: var(--md-code-font);
    font-size: 0.82rem;
    line-height: 1.6;
    padding: 0.75rem 1rem;
    background: var(--md-default-bg-color);
    border: 1px solid var(--md-default-fg-color--lightest);
    border-radius: 4px;
    overflow-x: auto;
    margin-bottom: 1rem;
  }
  .schema-field-name {
    color: var(--md-accent-fg-color);
  }
  .schema-type {
    color: var(--md-default-fg-color--light);
  }
  .schema-optional {
    color: var(--md-default-fg-color--lighter);
    font-style: italic;
    font-size: 0.78rem;
  }

  /* Example tabs */
  .example-tabs {
    margin-bottom: 1rem;
  }
  .example-tab-bar {
    display: flex;
    gap: 0;
    border-bottom: 2px solid var(--md-default-fg-color--lightest);
    margin-bottom: 0;
    flex-wrap: wrap;
  }
  .example-tab-btn {
    padding: 0.4rem 1rem;
    border: none;
    background: transparent;
    color: var(--md-default-fg-color--light);
    cursor: pointer;
    font-size: 0.82rem;
    border-bottom: 2px solid transparent;
    margin-bottom: -2px;
    font-family: inherit;
  }
  .example-tab-btn:hover {
    color: var(--md-default-fg-color);
  }
  .example-tab-btn.active {
    color: var(--md-accent-fg-color);
    border-bottom-color: var(--md-accent-fg-color);
  }
  .example-content {
    display: none;
  }
  .example-content.active {
    display: block;
  }
  .example-view-bar {
    display: flex;
    gap: 0;
    margin-top: 0.75rem;
    margin-bottom: 0;
  }
  .example-view-btn {
    padding: 0.35rem 0.9rem;
    border: 1px solid var(--md-default-fg-color--lightest);
    background: var(--md-default-bg-color);
    color: var(--md-default-fg-color--light);
    cursor: pointer;
    font-size: 0.78rem;
    font-family: inherit;
  }
  .example-view-btn:first-child {
    border-radius: 4px 0 0 0;
    border-right: none;
  }
  .example-view-btn:last-child {
    border-radius: 0 4px 0 0;
  }
  .example-view-btn.active {
    background: var(--md-accent-fg-color);
    color: var(--md-accent-bg-color);
    border-color: var(--md-accent-fg-color);
  }
  .example-pre {
    margin: 0;
    padding: 0.75rem;
    background: var(--md-default-bg-color);
    border: 1px solid var(--md-default-fg-color--lightest);
    border-top: none;
    border-radius: 0 0 4px 4px;
    font-size: 0.78rem;
    line-height: 1.5;
    overflow-x: auto;
    max-height: 400px;
    overflow-y: auto;
  }
  .detail-loading {
    padding: 1rem;
    color: var(--md-default-fg-color--light);
    font-size: 0.85rem;
  }
  .detail-error {
    padding: 1rem;
    color: #e53935;
    font-size: 0.85rem;
  }
  .no-data-msg {
    color: var(--md-default-fg-color--lighter);
    font-size: 0.85rem;
    font-style: italic;
  }
</style>

<script>
// IIFE — see previous fix for why we avoid DOMContentLoaded with
// MkDocs Material instant navigation.
;(function () {
  var versionSelect = document.getElementById("catalog-version");
  var search = document.getElementById("catalog-search");
  var osFilter = document.getElementById("catalog-os-filter");
  var tagFilter = document.getElementById("catalog-tag-filter");
  var tbody = document.getElementById("catalog-body");
  var stats = document.getElementById("catalog-stats");
  var empty = document.getElementById("catalog-empty");
  var table = document.getElementById("catalog-table");

  var currentParsers = [];
  var sortCol = "command";
  var sortDir = "asc";
  var detailCache = {};
  var expandedKey = null;

  var osDisplayNames = {
    "cisco_ios": "Cisco IOS",
    "cisco_iosxe": "Cisco IOS-XE",
    "cisco_iosxr": "Cisco IOS-XR",
    "cisco_nxos": "Cisco NX-OS"
  };

  function osLabel(os) {
    return osDisplayNames[os] || os;
  }

  function parserKey(p) {
    return p.os + "::" + p.command;
  }

  function setMessage(parent, className, text) {
    while (parent.firstChild) parent.removeChild(parent.firstChild);
    var div = document.createElement("div");
    div.className = className;
    div.textContent = text;
    parent.appendChild(div);
  }

  // --- Version loading ---

  fetch("versions.json")
    .then(function (r) { return r.json(); })
    .then(function (manifest) { initVersions(manifest); })
    .catch(function () {
      versionSelect.textContent = "";
      var opt = document.createElement("option");
      opt.textContent = "Failed to load versions";
      versionSelect.appendChild(opt);
    });

  function initVersions(manifest) {
    versionSelect.textContent = "";

    manifest.versions.forEach(function (v) {
      var opt = document.createElement("option");
      opt.value = v.file;
      opt.textContent = v.label;
      versionSelect.appendChild(opt);
    });

    var mainOpt = document.createElement("option");
    mainOpt.value = manifest.main.file;
    mainOpt.textContent = manifest.main.label;
    versionSelect.appendChild(mainOpt);

    var latestFile = manifest.versions.length > 0
      ? manifest.versions[0].file
      : manifest.main.file;
    versionSelect.value = latestFile;
    loadVersion(latestFile);

    versionSelect.addEventListener("change", function () {
      loadVersion(versionSelect.value);
    });
  }

  function loadVersion(file) {
    expandedKey = null;
    detailCache = {};
    fetch(file)
      .then(function (r) { return r.json(); })
      .then(function (parsers) {
        currentParsers = parsers;
        rebuildFilters();
        render();
      })
      .catch(function () {
        currentParsers = [];
        rebuildFilters();
        render();
        stats.textContent = "Failed to load parser data for this version.";
      });
  }

  // --- Filters ---

  function rebuildFilters() {
    search.value = "";

    osFilter.textContent = "";
    var allOsOpt = document.createElement("option");
    allOsOpt.value = "";
    allOsOpt.textContent = "All Platforms";
    osFilter.appendChild(allOsOpt);

    var osSet = [];
    currentParsers.forEach(function (p) {
      if (osSet.indexOf(p.os) === -1) osSet.push(p.os);
    });
    osSet.sort();
    osSet.forEach(function (os) {
      var opt = document.createElement("option");
      opt.value = os;
      opt.textContent = osLabel(os);
      osFilter.appendChild(opt);
    });

    tagFilter.textContent = "";
    var allTagOpt = document.createElement("option");
    allTagOpt.value = "";
    allTagOpt.textContent = "All Tags";
    tagFilter.appendChild(allTagOpt);

    var tagSet = [];
    currentParsers.forEach(function (p) {
      p.tags.forEach(function (t) {
        if (tagSet.indexOf(t) === -1) tagSet.push(t);
      });
    });
    tagSet.sort();
    tagSet.forEach(function (tag) {
      var opt = document.createElement("option");
      opt.value = tag;
      opt.textContent = tag;
      tagFilter.appendChild(opt);
    });
  }

  // --- Rendering ---

  function createTagChip(tag) {
    var span = document.createElement("span");
    span.className = "tag-chip";
    span.textContent = tag;
    return span;
  }

  function createRow(p) {
    var key = parserKey(p);
    var tr = document.createElement("tr");
    tr.className = "catalog-row";
    if (expandedKey === key) tr.classList.add("expanded");

    var tdExpand = document.createElement("td");
    tdExpand.className = "expand-cell";
    var chevron = document.createElement("span");
    chevron.textContent = "\u25B6";
    tdExpand.appendChild(chevron);
    tr.appendChild(tdExpand);

    var tdOs = document.createElement("td");
    tdOs.textContent = osLabel(p.os);
    tr.appendChild(tdOs);

    var tdCmd = document.createElement("td");
    var cmdSpan = document.createElement("span");
    cmdSpan.className = "command-text";
    cmdSpan.textContent = p.command;
    tdCmd.appendChild(cmdSpan);
    tr.appendChild(tdCmd);

    var tdTags = document.createElement("td");
    p.tags.forEach(function (t) {
      tdTags.appendChild(createTagChip(t));
    });
    tr.appendChild(tdTags);

    tr.addEventListener("click", function () {
      toggleDetail(p, tr);
    });

    return tr;
  }

  function render() {
    var q = search.value.toLowerCase();
    var osVal = osFilter.value;
    var tagVal = tagFilter.value;

    var filtered = currentParsers.filter(function (p) {
      if (q && p.command.toLowerCase().indexOf(q) === -1) return false;
      if (osVal && p.os !== osVal) return false;
      if (tagVal && p.tags.indexOf(tagVal) === -1) return false;
      return true;
    });

    filtered.sort(function (a, b) {
      var va = a[sortCol] || "";
      var vb = b[sortCol] || "";
      if (sortCol === "os") { va = osLabel(va); vb = osLabel(vb); }
      if (Array.isArray(va)) va = va.join(", ");
      if (Array.isArray(vb)) vb = vb.join(", ");
      var cmp = va.localeCompare(vb);
      return sortDir === "asc" ? cmp : -cmp;
    });

    while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

    filtered.forEach(function (p) {
      var row = createRow(p);
      tbody.appendChild(row);

      // Re-insert expanded detail row if this parser is expanded
      if (expandedKey === parserKey(p)) {
        var detailRow = createDetailRow();
        tbody.appendChild(detailRow);
        var panel = detailRow.querySelector(".detail-panel");
        var data = detailCache[parserKey(p)];
        if (data) {
          renderDetailContent(panel, data);
        } else {
          loadDetail(p, panel);
        }
      }
    });

    stats.textContent = "Showing " + filtered.length + " of " + currentParsers.length + " parsers";
    empty.style.display = filtered.length === 0 ? "block" : "none";
    table.style.display = filtered.length === 0 ? "none" : "table";

    table.querySelectorAll("th").forEach(function (th) {
      th.classList.remove("sort-asc", "sort-desc");
      if (th.dataset.sort === sortCol) {
        th.classList.add(sortDir === "asc" ? "sort-asc" : "sort-desc");
      }
    });
  }

  // --- Detail panel ---

  function createDetailRow() {
    var tr = document.createElement("tr");
    tr.className = "detail-row";
    var td = document.createElement("td");
    td.colSpan = 4;
    var panel = document.createElement("div");
    panel.className = "detail-panel";
    setMessage(panel, "detail-loading", "Loading details...");
    td.appendChild(panel);
    tr.appendChild(td);
    return tr;
  }

  function toggleDetail(p, rowEl) {
    var key = parserKey(p);

    if (expandedKey === key) {
      // Collapse
      expandedKey = null;
      rowEl.classList.remove("expanded");
      var next = rowEl.nextElementSibling;
      if (next && next.classList.contains("detail-row")) {
        next.parentNode.removeChild(next);
      }
      return;
    }

    // Collapse any previously expanded row
    var prevExpanded = tbody.querySelector("tr.catalog-row.expanded");
    if (prevExpanded) {
      prevExpanded.classList.remove("expanded");
      var prevDetail = prevExpanded.nextElementSibling;
      if (prevDetail && prevDetail.classList.contains("detail-row")) {
        prevDetail.parentNode.removeChild(prevDetail);
      }
    }

    // Expand this row
    expandedKey = key;
    rowEl.classList.add("expanded");

    var detailRow = createDetailRow();
    rowEl.parentNode.insertBefore(detailRow, rowEl.nextSibling);

    var panel = detailRow.querySelector(".detail-panel");
    var cached = detailCache[key];
    if (cached) {
      renderDetailContent(panel, cached);
    } else {
      loadDetail(p, panel);
    }
  }

  function loadDetail(p, panel) {
    var key = parserKey(p);
    if (!p.detail_file) {
      setMessage(panel, "detail-error", "No detail data available.");
      return;
    }
    fetch(p.detail_file)
      .then(function (r) { return r.json(); })
      .then(function (data) {
        detailCache[key] = data;
        if (expandedKey === key) {
          renderDetailContent(panel, data);
        }
      })
      .catch(function () {
        if (expandedKey === key) {
          setMessage(panel, "detail-error", "Failed to load parser details.");
        }
      });
  }

  function renderDetailContent(panel, data) {
    while (panel.firstChild) panel.removeChild(panel.firstChild);

    // Schema section
    var schemaHeading = document.createElement("h4");
    schemaHeading.textContent = "Schema";
    panel.appendChild(schemaHeading);

    if (data.schema) {
      var schemaEl = document.createElement("pre");
      schemaEl.className = "schema-tree";
      schemaEl.textContent = renderSchemaText(data.schema);
      panel.appendChild(schemaEl);
    } else {
      var noSchema = document.createElement("div");
      noSchema.className = "no-data-msg";
      noSchema.textContent = "No schema information available.";
      panel.appendChild(noSchema);
    }

    // Examples section
    var exHeading = document.createElement("h4");
    exHeading.textContent = "Examples";
    panel.appendChild(exHeading);

    if (data.examples && data.examples.length > 0) {
      panel.appendChild(renderExamples(data.examples));
    } else {
      var noEx = document.createElement("div");
      noEx.className = "no-data-msg";
      noEx.textContent = "No test fixture examples available.";
      panel.appendChild(noEx);
    }
  }

  // --- Schema rendering ---

  function renderSchemaText(schema) {
    var lines = [];
    renderTypedDict(schema, 0, lines, false);
    return lines.join("\n");
  }

  function indent(depth) {
    var s = "";
    for (var i = 0; i < depth; i++) s += "  ";
    return s;
  }

  function renderTypedDict(td, depth, lines, omitBraces) {
    if (!td || !td.fields) return;
    var fields = td.fields;
    var keys = Object.keys(fields);
    if (!omitBraces) lines.push(indent(depth) + "{");
    var inner = depth + 1;

    keys.forEach(function (name, i) {
      var field = fields[name];
      var keyStr = field.required ? '"' + name + '"' : '"' + name + '"?';
      var val = typeToJsonValue(field.type, inner, lines);
      var comma = i < keys.length - 1 ? "," : "";

      if (val.multiline) {
        lines.push(indent(inner) + keyStr + ": " + val.open);
        val.bodyFn();
        lines.push(indent(inner) + val.close + comma);
      } else {
        lines.push(indent(inner) + keyStr + ": " + val.text + comma);
      }
    });

    if (!omitBraces) lines.push(indent(depth) + "}");
  }

  function typeToJsonValue(t, depth, lines) {
    if (typeof t === "string") {
      return { text: "<" + t + ">", multiline: false };
    }

    if (!t) return { text: "<unknown>", multiline: false };

    // TypedDict
    if (t.fields && t.name) {
      return {
        multiline: true,
        open: "{",
        close: "}",
        bodyFn: function () { renderTypedDict(t, depth, lines, true); }
      };
    }

    if (t.type === "dict") {
      var keyPlaceholder = "<" + scalarName(t.key) + ">";
      var valResult = typeToJsonValue(t.value, depth + 1, lines);

      if (valResult.multiline) {
        return {
          multiline: true,
          open: "{",
          close: "}",
          bodyFn: function () {
            lines.push(indent(depth + 1) + keyPlaceholder + ": " + valResult.open);
            valResult.bodyFn();
            lines.push(indent(depth + 1) + valResult.close);
          }
        };
      }
      return {
        multiline: true,
        open: "{",
        close: "}",
        bodyFn: function () {
          lines.push(indent(depth + 1) + keyPlaceholder + ": " + valResult.text);
        }
      };
    }

    if (t.type === "list") {
      var itemResult = typeToJsonValue(t.items, depth + 1, lines);
      if (itemResult.multiline) {
        return {
          multiline: true,
          open: "[",
          close: "]",
          bodyFn: function () {
            lines.push(indent(depth + 1) + itemResult.open);
            itemResult.bodyFn();
            lines.push(indent(depth + 1) + itemResult.close);
          }
        };
      }
      return {
        multiline: true,
        open: "[",
        close: "]",
        bodyFn: function () {
          lines.push(indent(depth + 1) + itemResult.text);
        }
      };
    }

    if (t.type === "literal") {
      var vals = t.values.map(function (v) {
        return typeof v === "string" ? '"' + v + '"' : String(v);
      });
      return { text: vals.join(" | "), multiline: false };
    }

    if (t.type === "union") {
      var parts = t.options.map(function (o) { return scalarName(o); });
      return { text: "<" + parts.join(" | ") + ">", multiline: false };
    }

    return { text: "<" + String(t.type || t) + ">", multiline: false };
  }

  function scalarName(t) {
    if (typeof t === "string") return t;
    if (t && t.name) return t.name;
    if (t && t.type) return t.type;
    return "unknown";
  }

  // --- Example rendering ---

  function renderExamples(examples) {
    var container = document.createElement("div");
    container.className = "example-tabs";

    var bar = document.createElement("div");
    bar.className = "example-tab-bar";
    container.appendChild(bar);

    var panes = [];

    examples.forEach(function (ex, idx) {
      var btn = document.createElement("button");
      btn.className = "example-tab-btn";
      if (idx === 0) btn.classList.add("active");
      btn.textContent = ex.name;
      btn.addEventListener("click", function () {
        bar.querySelectorAll(".example-tab-btn").forEach(function (b) {
          b.classList.remove("active");
        });
        btn.classList.add("active");
        panes.forEach(function (pane, j) {
          pane.classList.toggle("active", j === idx);
        });
      });
      bar.appendChild(btn);

      var pane = document.createElement("div");
      pane.className = "example-content";
      if (idx === 0) pane.classList.add("active");

      // View toggle: CLI Output / Parsed Result
      var viewBar = document.createElement("div");
      viewBar.className = "example-view-bar";

      var cliBtn = document.createElement("button");
      cliBtn.className = "example-view-btn active";
      cliBtn.textContent = "CLI Output";
      viewBar.appendChild(cliBtn);

      var parsedBtn = document.createElement("button");
      parsedBtn.className = "example-view-btn";
      parsedBtn.textContent = "Parsed Result";
      viewBar.appendChild(parsedBtn);

      pane.appendChild(viewBar);

      var cliPre = document.createElement("pre");
      cliPre.className = "example-pre";
      cliPre.textContent = ex.input;
      pane.appendChild(cliPre);

      var parsedPre = document.createElement("pre");
      parsedPre.className = "example-pre";
      parsedPre.style.display = "none";
      parsedPre.textContent = JSON.stringify(ex.expected, null, 2);
      pane.appendChild(parsedPre);

      cliBtn.addEventListener("click", function () {
        cliBtn.classList.add("active");
        parsedBtn.classList.remove("active");
        cliPre.style.display = "";
        parsedPre.style.display = "none";
      });

      parsedBtn.addEventListener("click", function () {
        parsedBtn.classList.add("active");
        cliBtn.classList.remove("active");
        parsedPre.style.display = "";
        cliPre.style.display = "none";
      });

      container.appendChild(pane);
      panes.push(pane);
    });

    return container;
  }

  // --- Event listeners ---

  search.addEventListener("input", render);
  osFilter.addEventListener("change", render);
  tagFilter.addEventListener("change", render);

  table.querySelectorAll("th[data-sort]").forEach(function (th) {
    th.addEventListener("click", function () {
      if (sortCol === th.dataset.sort) {
        sortDir = sortDir === "asc" ? "desc" : "asc";
      } else {
        sortCol = th.dataset.sort;
        sortDir = "asc";
      }
      render();
    });
  });
})();
</script>
