/* map-shared.js - shared utilities for map pages */

function escapeHtml(str) {
  var el = document.createElement('span');
  el.textContent = str;
  return el.innerHTML;
}

function initMap(elementId, options) {
  var settings = options || {};
  if (!CSS.supports('height', '100dvh')) {
    document.body.style.height = window.innerHeight + 'px';
  }

  var map = L.map(elementId, {
    center: settings.center || [47.15, 19.35],
    zoom: settings.zoom != null ? settings.zoom : 8,
    minZoom: settings.minZoom != null ? settings.minZoom : 7,
    maxZoom: settings.maxZoom != null ? settings.maxZoom : 14,
    renderer: L.canvas()
  });

  L.tileLayer('https://{s}.basemaps.cartocdn.com/light_nolabels/{z}/{x}/{y}{r}.png', {
    attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> &copy; <a href="https://carto.com/">CARTO</a>',
    subdomains: 'abcd',
    maxZoom: 19
  }).addTo(map);

  L.tileLayer('https://{s}.basemaps.cartocdn.com/light_only_labels/{z}/{x}/{y}{r}.png', {
    subdomains: 'abcd',
    maxZoom: 19,
    pane: 'shadowPane'
  }).addTo(map);

  var resizeTimer;
  window.addEventListener('resize', function () {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(function () {
      map.invalidateSize({ animate: false });
    }, 100);
  });

  return map;
}

function normalizeMunicipalityId(value) {
  if (value == null) return '';
  var text = String(value);
  var match = text.match(/^[A-Z]{2}_(\d+)$/);
  return match ? match[1] : text;
}

function setupInfoBar(map) {
  function toggleInfo() {
    var bar = document.getElementById('info-bar');
    var btn = document.getElementById('toggle-info');
    bar.classList.toggle('collapsed');
    var collapsed = bar.classList.contains('collapsed');
    btn.innerHTML = collapsed ? 'About \u25be' : 'About \u25b4';
    btn.setAttribute('aria-expanded', String(!collapsed));
  }

  document.getElementById('toggle-info').addEventListener('click', function () {
    toggleInfo();
    map.invalidateSize({ animate: false });
  });

  if (window.innerWidth <= 600) {
    document.getElementById('info-bar').classList.add('collapsed');
    var btn = document.getElementById('toggle-info');
    btn.innerHTML = 'About \u25be';
    btn.setAttribute('aria-expanded', 'false');
  }
}

function toggleLegend() {
  var legend = document.querySelector('.legend');
  var btn = legend.querySelector('.legend-toggle');
  legend.classList.toggle('legend-collapsed');
  var collapsed = legend.classList.contains('legend-collapsed');
  btn.textContent = collapsed ? 'Legend \u25B8' : '\u2715';
  btn.setAttribute('aria-expanded', String(!collapsed));
}

function showGenerated(dnsData) {
  if (dnsData.generated) {
    var date = new Date(dnsData.generated);
    var text = 'Updated ' + date.toLocaleString('de-CH', { dateStyle: 'medium', timeStyle: 'short' });
    if (dnsData.commit) {
      text += ' \u00b7 commit ' + dnsData.commit;
    }
    document.getElementById('generated').textContent = text;
  }
}

function addLakes(map, topo, lakeColor) {
  if (topo.objects.lakes) {
    var lakes = topojson.feature(topo, topo.objects.lakes);
    return L.geoJSON(lakes, {
      interactive: false,
      style: { fillColor: lakeColor, fillOpacity: 1, weight: 0, color: 'transparent' }
    }).addTo(map);
  }
  return null;
}

async function fetchMapData() {
  async function fetchOptionalJson(url) {
    try {
      var response = await fetch(url);
      if (!response.ok) return null;
      return await response.json();
    } catch (err) {
      console.warn('Optional data load failed for', url, err);
      return null;
    }
  }

  var responses = await Promise.all([
    fetch('data/LAU_HU_01M_2024_3035.topo.json'),
    fetchOptionalJson('data/data.min.json'),
    fetchOptionalJson('data/municipality_domains.json')
  ]);

  if (!responses[0].ok) {
    throw new Error('Failed to load LAU topology: ' + responses[0].status);
  }

  return {
    topo: await responses[0].json(),
    classifiedData: responses[1],
    domainData: responses[2]
  };
}

function pickMunicipalityData(topo, datasets) {
  var geometries = topo &&
    topo.objects &&
    topo.objects.municipalities &&
    topo.objects.municipalities.geometries
    ? topo.objects.municipalities.geometries
    : [];

  var geometryIds = new Set(
    geometries.map(function (geometry) {
      return normalizeMunicipalityId(geometry.id || (geometry.properties && geometry.properties.GISCO_ID));
    })
  );

  var best = null;
  var bestScore = -1;

  datasets.forEach(function (dataset, priority) {
    if (!dataset || !dataset.municipalities) return;
    var municipalities = dataset.municipalities;
    var score = 0;
    Object.keys(municipalities).forEach(function (id) {
      if (geometryIds.has(normalizeMunicipalityId(id))) score++;
    });
    if (score > bestScore || (score === bestScore && best && priority < best.priority)) {
      best = { data: dataset, priority: priority };
      bestScore = score;
    }
  });

  return best ? best.data : { municipalities: {} };
}

function removeLoading() {
  var loading = document.getElementById('map-loading');
  if (loading) loading.remove();
}

function handleLoadError(err) {
  console.error('Failed to load data:', err);
  var loading = document.getElementById('map-loading');
  if (loading) {
    loading.textContent = 'Failed to load map data. Please try again later.';
    loading.style.color = '#dc2626';
  }
}
