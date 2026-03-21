from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QAction, QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from PySide6.QtCore import QUrl


class SizeTableWidgetItem(QTableWidgetItem):
    def __init__(self, size_bytes: int):
        super().__init__(format_bytes(size_bytes))
        self.size_bytes = size_bytes
        self.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)

    def __lt__(self, other):
        if isinstance(other, SizeTableWidgetItem):
            return self.size_bytes < other.size_bytes
        return super().__lt__(other)

try:
    from send2trash import send2trash
except Exception:
    send2trash = None


APP_NAME = "Mac Space Guard"
DEFAULT_SCAN_TARGETS = [
    Path.home() / "Library" / "Application Support",
    Path.home() / "Library" / "Containers",
    Path.home() / "Library" / "Group Containers",
    Path.home() / "Downloads",
    Path.home() / "Pictures",
]


@dataclass
class ScanResult:
    path: Path
    size_bytes: int
    category: str
    safety: str
    note: str


def format_bytes(num: int) -> str:
    step = 1024.0
    unit = "B"
    value = float(num)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if value < step:
            return f"{value:.1f} {unit}"
        value /= step
    return f"{value:.1f} PB"


RULES: dict[str, tuple[str, str, str]] = {
    "Google": ("Browser", "Revisar", "Pode conter perfil, cache e sessão do navegador."),
    "Chrome": ("Browser", "Revisar", "Pode conter perfil, cache e sessão do navegador."),
    "Code": ("IDE", "Seguro", "Normalmente contém cache e dados do VS Code."),
    "Cursor": ("IDE", "Seguro", "Geralmente cache e dados de editor."),
    "discord": ("Chat", "Seguro", "Cache e mídia local costumam crescer com o tempo."),
    "Notion": ("Produtividade", "Seguro", "Cache offline pode crescer bastante."),
    "OpenEmu": ("Emulação", "Revisar", "Pode conter ROMs, saves e BIOS."),
    "Docker": ("Dev", "Revisar", "Pode incluir imagens, volumes e containers."),
    "Android": ("Dev", "Revisar", "Pode conter SDK, AVD e builds."),
    "pyinstaller": ("Dev", "Seguro", "Artefatos de build antigos."),
    "minecraft": ("Jogos", "Revisar", "Pode conter mundos e mods do usuário."),
    "com.apple.wallpaper": ("Sistema", "Seguro", "Cache local de wallpapers."),
}


def classify(path: Path) -> tuple[str, str, str]:
    name = path.name
    for key, value in RULES.items():
        if key.lower() in name.lower():
            return value

    lowered = str(path).lower()
    if "cache" in lowered or "logs" in lowered:
        return ("Cache/Logs", "Seguro", "Itens geralmente recuperáveis.")
    if "container" in lowered:
        return ("Containers", "Revisar", "Pode conter dados persistidos de apps.")
    return ("Outros", "Revisar", "Revisar antes de limpar.")


class ScannerThread(QThread):
    progress = Signal(int)
    finished_scan = Signal(list)
    failed = Signal(str)

    def __init__(self, targets: Iterable[Path]):
        super().__init__()
        self.targets = [t for t in targets if t.exists()]

    def run(self) -> None:
        try:
            results: list[ScanResult] = []
            if not self.targets:
                self.finished_scan.emit(results)
                return

            total = len(self.targets)
            for index, target in enumerate(self.targets, start=1):
                for child in self.safe_iterdir(target):
                    size = self.get_size(child)
                    category, safety, note = classify(child)
                    results.append(
                        ScanResult(
                            path=child,
                            size_bytes=size,
                            category=category,
                            safety=safety,
                            note=note,
                        )
                    )
                self.progress.emit(int(index / total * 100))

            results.sort(key=lambda item: item.size_bytes, reverse=True)
            self.finished_scan.emit(results)
        except Exception as exc:
            self.failed.emit(str(exc))

    def safe_iterdir(self, path: Path) -> Iterable[Path]:
        try:
            yield from path.iterdir()
        except PermissionError:
            return
        except FileNotFoundError:
            return

    def get_size(self, path: Path) -> int:
        try:
            if path.is_symlink():
                return 0
            if path.is_file():
                return path.stat().st_size

            total = 0
            for root, dirs, files in os.walk(path, onerror=lambda e: None):
                dirs[:] = [d for d in dirs if not Path(root, d).is_symlink()]
                for file_name in files:
                    file_path = Path(root) / file_name
                    try:
                        if not file_path.is_symlink():
                            total += file_path.stat().st_size
                    except (PermissionError, FileNotFoundError, OSError):
                        continue
            return total
        except (PermissionError, FileNotFoundError, OSError):
            return 0


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.resize(1100, 700)
        self.results: list[ScanResult] = []
        self.thread: ScannerThread | None = None

        self.status_label = QLabel("Pronto para escanear.")
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Pasta", "Tamanho", "Categoria", "Segurança", "Observação"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSortingEnabled(True)

        # Ajuste de largura inicial
        self.table.setColumnWidth(0, 500)  # Pasta
        self.table.setColumnWidth(1, 120)  # Tamanho
        self.table.setColumnWidth(2, 120)  # Categoria
        self.table.setColumnWidth(3, 100)  # Segurança

        scan_button = QPushButton("Escanear áreas padrão")
        scan_button.clicked.connect(self.start_default_scan)

        custom_button = QPushButton("Escanear outra pasta")
        custom_button.clicked.connect(self.scan_custom_folder)

        reveal_button = QPushButton("Abrir no Finder")
        reveal_button.clicked.connect(self.reveal_selected)

        trash_button = QPushButton("Mover para Lixeira")
        trash_button.clicked.connect(self.trash_selected)

        top_bar = QHBoxLayout()
        top_bar.addWidget(scan_button)
        top_bar.addWidget(custom_button)
        top_bar.addStretch()
        top_bar.addWidget(reveal_button)
        top_bar.addWidget(trash_button)

        root = QWidget()
        layout = QVBoxLayout(root)
        layout.addLayout(top_bar)
        layout.addWidget(self.status_label)
        layout.addWidget(self.progress)
        layout.addWidget(self.table)
        self.setCentralWidget(root)

        exit_action = QAction("Sair", self)
        exit_action.triggered.connect(self.close)
        self.menuBar().addAction(exit_action)

    def start_default_scan(self) -> None:
        self.start_scan(DEFAULT_SCAN_TARGETS)

    def scan_custom_folder(self) -> None:
        selected = QFileDialog.getExistingDirectory(self, "Escolha a pasta para escanear")
        if selected:
            self.start_scan([Path(selected)])

    def start_scan(self, targets: list[Path]) -> None:
        self.progress.setValue(0)
        self.status_label.setText("Escaneando...")
        self.table.setRowCount(0)
        self.results = []

        self.thread = ScannerThread(targets)
        self.thread.progress.connect(self.progress.setValue)
        self.thread.finished_scan.connect(self.populate_table)
        self.thread.failed.connect(self.show_error)
        self.thread.start()

    def populate_table(self, results: list[ScanResult]) -> None:
        self.results = results
        self.table.setRowCount(len(results))

        for row, item in enumerate(results):
            self.table.setItem(row, 0, QTableWidgetItem(str(item.path)))
            self.table.setItem(row, 1, SizeTableWidgetItem(item.size_bytes))
            self.table.setItem(row, 2, QTableWidgetItem(item.category))

        self.table.resizeColumnsToContents()
        total_space = sum(x.size_bytes for x in results)
        self.status_label.setText(
            f"Escaneamento concluído. {len(results)} itens encontrados | Total analisado: {format_bytes(total_space)}"
        )
        self.progress.setValue(100)

    def selected_result(self) -> ScanResult | None:
        selected = self.table.selectionModel().selectedRows()
        if not selected:
            QMessageBox.information(self, APP_NAME, "Selecione uma linha primeiro.")
            return None
        row = selected[0].row()
        return self.results[row]

    def reveal_selected(self) -> None:
        item = self.selected_result()
        if not item:
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(item.path)))

    def trash_selected(self) -> None:
        item = self.selected_result()
        if not item:
            return

        if send2trash is None:
            QMessageBox.warning(
                self,
                APP_NAME,
                "A biblioteca send2trash não está instalada. Instale com: pip install send2trash",
            )
            return

        if item.safety == "Revisar":
            answer = QMessageBox.question(
                self,
                APP_NAME,
                "Esse item está marcado como 'Revisar'. Deseja mesmo mover para a Lixeira?",
            )
            if answer != QMessageBox.Yes:
                return
        else:
            answer = QMessageBox.question(
                self,
                APP_NAME,
                f"Mover para a Lixeira?\n\n{item.path}",
            )
            if answer != QMessageBox.Yes:
                return

        try:
            send2trash(str(item.path))
            QMessageBox.information(self, APP_NAME, "Item movido para a Lixeira.")
            self.start_default_scan()
        except Exception as exc:
            QMessageBox.critical(self, APP_NAME, f"Não foi possível mover para a Lixeira:\n{exc}")

    def show_error(self, message: str) -> None:
        QMessageBox.critical(self, APP_NAME, f"Erro durante o escaneamento:\n{message}")
        self.status_label.setText("Falha ao escanear.")
        self.progress.setValue(0)


def main() -> None:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
