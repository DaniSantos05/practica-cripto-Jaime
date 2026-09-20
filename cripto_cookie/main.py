"""Punto de entrada de la aplicación de notas seguras CryptoNotes."""

from __future__ import annotations

import sys

import pygame

from core import settings
from core.core import AplicacionNotas


def main() -> None:
    pygame.init()
    pygame.display.set_caption(settings.TITLE)
    screen = pygame.display.set_mode((settings.WIDTH, settings.HEIGHT))
    clock = pygame.time.Clock()
    application = AplicacionNotas(settings.WIDTH, settings.HEIGHT)

    running = True
    while running:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                running = False
            else:
                application.handle_event(event)
        application.update()
        application.draw(screen)
        pygame.display.flip()
        clock.tick(settings.FPS)

    pygame.quit()
    sys.exit(0)


if __name__ == "__main__":
    main()
