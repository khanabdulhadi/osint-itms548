import sys, threading, qdarkstyle
from pathlib import Path
from PyQt5 import QtWidgets, QtCore, QtGui, QtWebEngineWidgets 
from data_sources import ip_api, subdomains, gdelt, wikidata, urlscan
from analysis.data_aggregator import save_csv


class LoadingOverlay(QtWidgets.QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.setAttribute(QtCore.Qt.WA_NoSystemBackground)
        self.setAttribute(QtCore.Qt.WA_TransparentForMouseEvents, False)
        self.setStyleSheet("background: rgba(0,0,0,0.3);")
        self.spinner = QtWidgets.QLabel(self)
        movie = QtGui.QMovie("spinner.gif")  # Place a spinner.gif in your working dir
        self.spinner.setMovie(movie)
        movie.start()
        self.spinner.setFixedSize(64, 64)
        self.hide()

    def resizeEvent(self, event):
        w, h = self.width(), self.height()
        sw, sh = self.spinner.width(), self.spinner.height()
        self.spinner.move((w - sw) // 2, (h - sh) // 2)
        super().resizeEvent(event)

    def start(self):
        self.resize(self.parent().size())
        self.show()

    def stop(self):
        self.hide()


class BaseTab(QtWidgets.QWidget):
    def style_button(self, btn: QtWidgets.QPushButton):
        btn.setFont(QtGui.QFont("Segoe UI", 12, QtGui.QFont.Bold))
        btn.setMinimumSize(140, 36)
        btn.setCursor(QtCore.Qt.PointingHandCursor)
        # subtle hover effect:
        btn.setStyleSheet("""
            QPushButton {
                background-color: #2E7D32;
                color: white;
                border-radius: 10px;
            }
            QPushButton:hover {
                background-color: #388E3C;
            }
        """)


class GeolocationTab(BaseTab):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.data = None
        self._build_ui()
        self.search_btn.clicked.connect(self._on_search)

    def _build_ui(self):
        self.setContentsMargins(10, 10, 10, 10)
        self.setLayout(QtWidgets.QVBoxLayout())
        self.layout().setSpacing(8)

        # Input group
        inp = QtWidgets.QGroupBox("IP / Hostname Lookup")
        il = QtWidgets.QHBoxLayout(inp)
        self.ip_input = QtWidgets.QLineEdit()
        self.ip_input.setPlaceholderText("e.g. 8.8.8.8 or example.com")
        self.search_btn = QtWidgets.QPushButton("Search")
        self.style_button(self.search_btn)
        il.addWidget(self.ip_input)
        il.addWidget(self.search_btn)

        # Results table
        res = QtWidgets.QGroupBox("Geolocation Lookup")
        rl = QtWidgets.QVBoxLayout(res)
        self.table = QtWidgets.QTableWidget(0, 2)
        # ↑ increase header font
        header_font = QtGui.QFont("Segoe UI", 11, QtGui.QFont.Bold)
        self.table.horizontalHeader().setFont(header_font)
        self.table.setHorizontalHeaderLabels(["Key", "Value"])
        self.table.horizontalHeader().setStretchLastSection(True)
        rl.addWidget(self.table)

        # Map view (hidden until data arrives)
        self.map_view = QtWebEngineWidgets.QWebEngineView()
        self.map_view.setMinimumHeight(300)
        self.map_view.hide()

        # Vertical splitter between table & map
        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        splitter.addWidget(res)
        splitter.addWidget(self.map_view)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        # Assemble layout
        self.layout().addWidget(inp)
        self.layout().addWidget(splitter)

        # Loading overlay
        self.overlay = LoadingOverlay(self)

    def _on_search(self):
        ip = self.ip_input.text().strip()
        if not ip:
            return
        self.table.setRowCount(0)
        self.map_view.hide()
        self.overlay.start()
        threading.Thread(target=self._lookup, args=(ip,), daemon=True).start()

    def _lookup(self, ip):
        res = ip_api.lookup(ip)
        QtCore.QMetaObject.invokeMethod(
            self, "_on_result", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(dict, res)
        )

    @QtCore.pyqtSlot(dict)
    def _on_result(self, res):
        self.overlay.stop()
        self.data = res
        for key, val in res.items():
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(str(key)))
            self.table.setItem(row, 1, QtWidgets.QTableWidgetItem(str(val)))

        lat, lon = res.get("lat"), res.get("lon")
        if lat is not None and lon is not None:
            html = f"""
            <!DOCTYPE html><html><head>
            <meta charset='utf-8'><title>Map</title>
            <link rel='stylesheet' href='https://unpkg.com/leaflet/dist/leaflet.css'/>
            <script src='https://unpkg.com/leaflet/dist/leaflet.js'></script>
            <style>html,body,#map{{height:100%;margin:0}}</style>
            </head><body><div id='map'></div>
            <script>
              var map=L.map('map').setView([{lat},{lon}],13);
              L.tileLayer('https://tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png',{{maxZoom:19}}).addTo(map);
              L.marker([{lat},{lon}]).addTo(map).bindPopup('IP Location').openPopup();
            </script></body></html>
            """
            self.map_view.setHtml(html)
            self.map_view.show()


class DomainLookupTab(BaseTab):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.data = None
        self._build_ui()
        self.search_btn.clicked.connect(self._on_search)

    def _build_ui(self):
        self.setContentsMargins(10, 10, 10, 10)
        self.setLayout(QtWidgets.QVBoxLayout())
        self.layout().setSpacing(8)

        inp = QtWidgets.QGroupBox("DNS Host Records")
        il = QtWidgets.QHBoxLayout(inp)
        self.domain_input = QtWidgets.QLineEdit()
        self.domain_input.setPlaceholderText("e.g. example.com")
        self.search_btn = QtWidgets.QPushButton("Search")
        self.style_button(self.search_btn)
        il.addWidget(self.domain_input)
        il.addWidget(self.search_btn)

        res = QtWidgets.QGroupBox("Subdomains")
        rl = QtWidgets.QVBoxLayout(res)
        self.table = QtWidgets.QTableWidget(0, 1)
        header_font = QtGui.QFont("Segoe UI", 11, QtGui.QFont.Bold)
        self.table.horizontalHeader().setFont(header_font)
        self.table.setHorizontalHeaderLabels(["Subdomain"])
        self.table.horizontalHeader().setStretchLastSection(True)
        rl.addWidget(self.table)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        splitter.addWidget(inp)
        splitter.addWidget(res)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 4)

        self.layout().addWidget(splitter)
        self.overlay = LoadingOverlay(self)

    def _on_search(self):
        dom = self.domain_input.text().strip()
        if not dom:
            return
        self.table.setRowCount(0)
        self.overlay.start()
        threading.Thread(target=self._lookup, args=(dom,), daemon=True).start()

    def _lookup(self, dom):
        subs = subdomains.get_subdomains(dom)
        QtCore.QMetaObject.invokeMethod(
            self, "_on_result", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(list, subs)
        )

    @QtCore.pyqtSlot(list)
    def _on_result(self, subs):
        self.overlay.stop()
        self.data = subs
        for s in subs:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(s))


class KeywordSearchTab(BaseTab):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.data = {}
        self._build_ui()
        self.search_btn.clicked.connect(self._on_search)

    def _build_ui(self):
        self.setContentsMargins(10, 10, 10, 10)
        self.setLayout(QtWidgets.QVBoxLayout())
        self.layout().setSpacing(8)

        inp = QtWidgets.QGroupBox("Keyword Search")
        il = QtWidgets.QHBoxLayout(inp)
        self.keyword_input = QtWidgets.QLineEdit()
        self.keyword_input.setPlaceholderText("Enter a keyword")
        self.search_btn = QtWidgets.QPushButton("Search")
        self.style_button(self.search_btn)
        il.addWidget(self.keyword_input)
        il.addWidget(self.search_btn)

        res = QtWidgets.QGroupBox("Results")
        rl = QtWidgets.QVBoxLayout(res)
        self.tree = QtWidgets.QTreeWidget()
        header_font = QtGui.QFont("Segoe UI", 11, QtGui.QFont.Bold)
        self.tree.header().setFont(header_font)
        self.tree.setHeaderLabels(["Source", "Title / Label", "Info"])
        rl.addWidget(self.tree)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        splitter.addWidget(inp)
        splitter.addWidget(res)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 4)

        self.layout().addWidget(splitter)
        self.overlay = LoadingOverlay(self)

    def _on_search(self):
        kw = self.keyword_input.text().strip()
        if not kw:
            return
        self.tree.clear()
        self.overlay.start()
        threading.Thread(target=self._lookup, args=(kw,), daemon=True).start()

    def _lookup(self, kw):
        arts = gdelt.search_articles(kw)[:10]
        ents = wikidata.entity_search(kw)
        QtCore.QMetaObject.invokeMethod(
            self, "_on_result", QtCore.Qt.QueuedConnection,
            QtCore.Q_ARG(list, arts), QtCore.Q_ARG(list, ents)
        )

    @QtCore.pyqtSlot(list, list)
    def _on_result(self, articles, entities):
        self.overlay.stop()
        self.data = {"gdelt": articles, "wikidata": entities}

        gdelt_root = QtWidgets.QTreeWidgetItem(self.tree, ["GDELT"])
        for art in articles:
            title = art.get("title", "<no-title>")
            src = art.get("domain", art.get("source", "N/A"))
            QtWidgets.QTreeWidgetItem(gdelt_root, ["", title, src])

        wiki_root = QtWidgets.QTreeWidgetItem(self.tree, ["Wikidata"])
        for ent in entities:
            lbl = ent.get("label", "")
            desc = ent.get("description", "")
            QtWidgets.QTreeWidgetItem(wiki_root, ["", lbl, desc])

        self.tree.expandAll()


class URLScanTab(BaseTab):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.data = None
        self._build_ui()
        self.search_btn.clicked.connect(self._on_search)

    def _build_ui(self):
        self.setContentsMargins(10, 10, 10, 10)
        self.setLayout(QtWidgets.QVBoxLayout())
        self.layout().setSpacing(8)

        inp = QtWidgets.QGroupBox("URL Scan")
        il = QtWidgets.QHBoxLayout(inp)
        self.url_input = QtWidgets.QLineEdit()
        self.url_input.setPlaceholderText("e.g. example.com")
        self.search_btn = QtWidgets.QPushButton("Search")
        self.style_button(self.search_btn)
        il.addWidget(self.url_input)
        il.addWidget(self.search_btn)

        res = QtWidgets.QGroupBox("Scan Results")
        rl = QtWidgets.QVBoxLayout(res)
        headers = ["Domain", "IP", "PTR", "ASN", "ASN Name", "URL"]
        self.table = QtWidgets.QTableWidget(0, len(headers))
        header_font = QtGui.QFont("Segoe UI", 11, QtGui.QFont.Bold)
        self.table.horizontalHeader().setFont(header_font)
        self.table.setHorizontalHeaderLabels(headers)
        self.table.horizontalHeader().setStretchLastSection(True)
        rl.addWidget(self.table)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        splitter.addWidget(inp)
        splitter.addWidget(res)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 4)

        self.layout().addWidget(splitter)
        self.overlay = LoadingOverlay(self)

    def _on_search(self):
        url = self.url_input.text().strip()
        if not url:
            return
        self.table.setRowCount(0)
        self.overlay.start()
        threading.Thread(target=self._lookup, args=(url,), daemon=True).start()

    def _lookup(self, url):
        scans = urlscan.search(url)
        target = url.lower().split("//")[-1].split("/")[0]
        filtered = [s for s in scans if target in s.get("page", {}).get("url", "")]
        QtCore.QMetaObject.invokeMethod(
            self, "_on_result", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(list, filtered)
        )

    @QtCore.pyqtSlot(list)
    def _on_result(self, scans):
        self.overlay.stop()
        self.data = scans
        for s in scans:
            page = s.get("page", {})
            row = self.table.rowCount()
            self.table.insertRow(row)
            vals = [
                page.get("domain", ""),
                page.get("ip", ""),
                page.get("ptr", ""),
                page.get("asn", ""),
                page.get("asnname", ""),
                page.get("url", "")
            ]
            for col, v in enumerate(vals):
                self.table.setItem(row, col, QtWidgets.QTableWidgetItem(str(v)))


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("OSINT Dashboard")
        self.resize(1200, 800)

        # Apply dark mode by default
        QtWidgets.QApplication.instance().setStyleSheet(
            qdarkstyle.load_stylesheet_pyqt5()
        )
        QtWidgets.QApplication.instance().setFont(QtGui.QFont("Segoe UI", 10))

        # Tabs
        self.tabs = QtWidgets.QTabWidget()
        self.tabs.addTab(GeolocationTab(), "Geolocation Lookup")
        self.tabs.addTab(DomainLookupTab(), "DNS Hosts Record")
        self.tabs.addTab(KeywordSearchTab(), "Keyword Search")
        self.tabs.addTab(URLScanTab(), "URL Scan")

        central = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(central)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.addWidget(self.tabs)

        export_btn = QtWidgets.QPushButton("Export CSV")
        export_btn.setFont(QtGui.QFont("Segoe UI", 12, QtGui.QFont.Bold))
        export_btn.setMinimumSize(140, 36)
        export_btn.setCursor(QtCore.Qt.PointingHandCursor)
        export_btn.setStyleSheet("""
            QPushButton {
                background-color: #C62828;
                color: white;
                border-radius: 10px;
            }
            QPushButton:hover {
                background-color: #E53935;
            }
        """)
        export_btn.setIcon(QtGui.QIcon.fromTheme("document-save"))
        export_btn.clicked.connect(self.export_all)
        self.statusBar().addPermanentWidget(export_btn)

        self.setCentralWidget(central)

    def export_all(self):
        data = {
            "ip": getattr(self.tabs.widget(0), "data", None),
            "domain": getattr(self.tabs.widget(1), "data", None),
            "keyword": getattr(self.tabs.widget(2), "data", None),
            "urlscan": getattr(self.tabs.widget(3), "data", None),
        }
        data = {k: v for k, v in data.items() if v}
        if not data:
            QtWidgets.QMessageBox.warning(self, "Nothing to export",
                                          "Run at least one lookup first")
            return
        folder = save_csv(data)
        QtWidgets.QMessageBox.information(
            self, "Exported", f"CSVs saved to:\n{Path(folder).resolve()}"
        )


def run_app():
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    run_app()
