# Parser Library

Browse all parsers available in Muninn. Use the search box and filters to find parsers by command, OS, or feature tag.

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
  #catalog-table tr:hover td {
    background: var(--md-code-bg-color);
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
</style>

<script>
// Use an IIFE instead of DOMContentLoaded — MkDocs Material's instant
// navigation (XHR page swaps) never re-fires DOMContentLoaded, so the
// catalog wouldn't initialise on first visit via an in-site link.
// The inline script sits below the HTML it references, so the elements
// already exist when this executes.
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

  // Human-readable OS display names
  var osDisplayNames = {
    "cisco_ios": "Cisco IOS",
    "cisco_iosxe": "Cisco IOS-XE",
    "cisco_iosxr": "Cisco IOS-XR",
    "cisco_nxos": "Cisco NX-OS"
  };

  function osLabel(os) {
    return osDisplayNames[os] || os;
  }

  // Load versions manifest
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
    // Clear loading placeholder
    versionSelect.textContent = "";

    // Add released versions (newest first)
    manifest.versions.forEach(function (v) {
      var opt = document.createElement("option");
      opt.value = v.file;
      opt.textContent = v.label;
      versionSelect.appendChild(opt);
    });

    // Add main at the bottom
    var mainOpt = document.createElement("option");
    mainOpt.value = manifest.main.file;
    mainOpt.textContent = manifest.main.label;
    versionSelect.appendChild(mainOpt);

    // Select the latest release by default
    var latestFile = manifest.versions.length > 0
      ? manifest.versions[0].file
      : manifest.main.file;
    versionSelect.value = latestFile;

    // Load the default version
    loadVersion(latestFile);

    // Switch versions on change
    versionSelect.addEventListener("change", function () {
      loadVersion(versionSelect.value);
    });
  }

  function loadVersion(file) {
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

  function rebuildFilters() {
    // Reset search
    search.value = "";

    // Rebuild OS filter
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

    // Rebuild tag filter
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

  function createTagChip(tag) {
    var span = document.createElement("span");
    span.className = "tag-chip";
    span.textContent = tag;
    return span;
  }

  function createRow(p) {
    var tr = document.createElement("tr");

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

    // Sort
    filtered.sort(function (a, b) {
      var va = a[sortCol] || "";
      var vb = b[sortCol] || "";
      if (sortCol === "os") { va = osLabel(va); vb = osLabel(vb); }
      if (Array.isArray(va)) va = va.join(", ");
      if (Array.isArray(vb)) vb = vb.join(", ");
      var cmp = va.localeCompare(vb);
      return sortDir === "asc" ? cmp : -cmp;
    });

    // Clear existing rows
    while (tbody.firstChild) {
      tbody.removeChild(tbody.firstChild);
    }

    // Build rows
    filtered.forEach(function (p) {
      tbody.appendChild(createRow(p));
    });

    stats.textContent = "Showing " + filtered.length + " of " + currentParsers.length + " parsers";
    empty.style.display = filtered.length === 0 ? "block" : "none";
    table.style.display = filtered.length === 0 ? "none" : "table";

    // Update sort indicators
    table.querySelectorAll("th").forEach(function (th) {
      th.classList.remove("sort-asc", "sort-desc");
      if (th.dataset.sort === sortCol) {
        th.classList.add(sortDir === "asc" ? "sort-asc" : "sort-desc");
      }
    });
  }

  // Event listeners
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
