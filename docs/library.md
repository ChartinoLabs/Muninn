# Parser Library

Browse all parsers available in Muninn. Use the search box and filters to find parsers by command, OS, or feature tag.

<div id="parser-catalog">
  <div class="catalog-controls">
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
document.addEventListener("DOMContentLoaded", function () {
  var dataUrl = "../catalog-data.json";

  fetch(dataUrl)
    .then(function (r) { return r.json(); })
    .then(function (parsers) { initCatalog(parsers); })
    .catch(function () {
      var tbody = document.getElementById("catalog-body");
      var tr = document.createElement("tr");
      var td = document.createElement("td");
      td.setAttribute("colspan", "3");
      td.textContent = "Parser catalog data not found. Run 'uv run python scripts/generate_catalog.py' to generate it.";
      tr.appendChild(td);
      tbody.appendChild(tr);
    });

  function initCatalog(parsers) {
    var tbody = document.getElementById("catalog-body");
    var search = document.getElementById("catalog-search");
    var osFilter = document.getElementById("catalog-os-filter");
    var tagFilter = document.getElementById("catalog-tag-filter");
    var stats = document.getElementById("catalog-stats");
    var empty = document.getElementById("catalog-empty");
    var table = document.getElementById("catalog-table");

    // Populate OS filter
    var osSet = [];
    parsers.forEach(function (p) {
      if (osSet.indexOf(p.os) === -1) osSet.push(p.os);
    });
    osSet.sort();
    osSet.forEach(function (os) {
      var opt = document.createElement("option");
      opt.value = os;
      opt.textContent = os;
      osFilter.appendChild(opt);
    });

    // Populate tag filter
    var tagSet = [];
    parsers.forEach(function (p) {
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

    var sortCol = "command";
    var sortDir = "asc";

    function createTagChip(tag) {
      var span = document.createElement("span");
      span.className = "tag-chip";
      span.textContent = tag;
      return span;
    }

    function createRow(p) {
      var tr = document.createElement("tr");

      var tdOs = document.createElement("td");
      tdOs.textContent = p.os;
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

      var filtered = parsers.filter(function (p) {
        if (q && p.command.toLowerCase().indexOf(q) === -1) return false;
        if (osVal && p.os !== osVal) return false;
        if (tagVal && p.tags.indexOf(tagVal) === -1) return false;
        return true;
      });

      // Sort
      filtered.sort(function (a, b) {
        var va = a[sortCol] || "";
        var vb = b[sortCol] || "";
        if (Array.isArray(va)) va = va.join(", ");
        if (Array.isArray(vb)) vb = vb.join(", ");
        var cmp = va.localeCompare(vb);
        return sortDir === "asc" ? cmp : -cmp;
      });

      // Clear existing rows
      while (tbody.firstChild) {
        tbody.removeChild(tbody.firstChild);
      }

      // Build rows with safe DOM methods
      filtered.forEach(function (p) {
        tbody.appendChild(createRow(p));
      });

      stats.textContent = "Showing " + filtered.length + " of " + parsers.length + " parsers";
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

    render();
  }
});
</script>
