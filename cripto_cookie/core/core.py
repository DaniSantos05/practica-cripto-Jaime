"""Coordinador entre la interfaz de notas y el cliente criptográfico."""

from __future__ import annotations

import pygame

from core import settings
from core.manejador_datos import ManejadorDatos
from core.menu import Menu


class AplicacionNotas:
    def __init__(self, width: int, height: int):
        self.menu = Menu(width, height)
        self.data_client = ManejadorDatos()

    def update(self) -> None:
        self.menu.update()

    def draw(self, screen: pygame.Surface) -> None:
        self.menu.draw(screen)

    def handle_event(self, event: pygame.event.Event) -> None:
        action = self.menu.handle_event(event)
        if action is None:
            return
        if isinstance(action, tuple):
            action_type, payload = action
            if action_type == "usuario_registrado":
                self._register(payload)
            elif action_type == "intento_login":
                self._login(payload)
            elif action_type == "guardar_nota":
                self._save_note(payload)
            elif action_type == "eliminar_nota":
                self._delete_note(payload)
            return
        if action == "refrescar":
            self._refresh_notes()
        elif action == "logout":
            self._logout()

    def _register(self, data: dict) -> None:
        result = self.data_client.registrar_usuario(data)
        if result is None:
            self.menu.formulario_registro.mostrar_resultado(
                self.data_client.last_error or "No se pudo completar el registro",
                settings.DANGER,
            )
            return
        self.menu.login_usuario(result["usuario"], result["notes"])
        self.menu.show_message("Bóveda creada correctamente")

    def _login(self, data: dict) -> None:
        result = self.data_client.validar_login(data)
        if result is None:
            self.menu.formulario_login.mostrar_resultado_login(
                False, self.data_client.last_error or "Credenciales inválidas"
            )
            return
        self.menu.login_usuario(result["usuario"], result["notes"])
        self.menu.show_message("Bóveda abierta y notas verificadas")

    def _save_note(self, data: dict) -> None:
        notes = self.data_client.guardar_nota(
            data.get("title", ""),
            data.get("content", ""),
            data.get("id"),
        )
        if notes is None:
            self.menu.show_message(
                self.data_client.last_error or "No se pudo guardar la nota",
                settings.DANGER,
            )
            return
        self.menu.set_notas(notes)
        self.menu.show_message("Nota cifrada y guardada correctamente")

    def _delete_note(self, note_id: str) -> None:
        notes = self.data_client.eliminar_nota(note_id)
        if notes is None:
            self.menu.show_message(
                self.data_client.last_error or "No se pudo eliminar la nota",
                settings.DANGER,
            )
            return
        self.menu.set_notas(notes)
        self.menu.show_message("Nota eliminada")

    def _refresh_notes(self) -> None:
        notes = self.data_client.listar_notas()
        if notes is None:
            self.menu.show_message(
                self.data_client.last_error or "No se pudieron actualizar las notas",
                settings.DANGER,
            )
            return
        self.menu.set_notas(notes)
        self.menu.show_message("Notas verificadas y actualizadas")

    def _logout(self) -> None:
        if not self.data_client.logout():
            self.menu.show_message(
                self.data_client.last_error or "El servidor no confirmó el cierre",
                settings.WARNING,
            )
        self.menu.logout_usuario()


# Alias temporal para no romper importaciones externas del proyecto anterior.
Juego = AplicacionNotas
