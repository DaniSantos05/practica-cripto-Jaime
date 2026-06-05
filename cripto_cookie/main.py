"""
Cookie Clicker Game - Punto de entrada principal
Juego estilo Cookie Clicker con sistema de usuarios y microtransacciones
"""
import pygame
import sys
import math
from core import settings
from core.core import Juego


def inicializar_pygame():
    """Inicializar pygame y configurar la ventana"""
    pygame.init()
    screen = pygame.display.set_mode((settings.WIDTH, settings.HEIGHT))
    pygame.display.set_caption("Cookie Clicker - ¡Haz click en la galleta!")
    return screen


def dibujar_fondo_cocina(surface):
    """Dibuja un fondo estilo cocina: azulejos y encimera de madera.
    Cachea el render en una Surface para no recalcular cada frame.
    """
    # Static cache en atributo de función
    if not hasattr(dibujar_fondo_cocina, "_cache"):
        dibujar_fondo_cocina._cache = None

    if dibujar_fondo_cocina._cache is None:
        bg = pygame.Surface((settings.WIDTH, settings.HEIGHT), pygame.SRCALPHA)

        # 1) Pared de azulejos superiores
        tile_w, tile_h = 64, 64
        wall_height = int(settings.HEIGHT * 0.65)
        base_color = (230, 235, 240)  # gris-azulado claro tipo azulejo
        grout = (200, 205, 210)       # junta

        # Fondo base
        bg.fill(base_color)

        # Líneas de juntas verticales y horizontales
        for x in range(0, settings.WIDTH, tile_w):
            pygame.draw.line(bg, grout, (x, 0), (x, wall_height), 2)
        for y in range(0, wall_height, tile_h):
            pygame.draw.line(bg, grout, (0, y), (settings.WIDTH, y), 2)

        # Ligeras variaciones de tono por azulejo
        for x in range(0, settings.WIDTH, tile_w):
            for y in range(0, wall_height, tile_h):
                tint = (5 if ((x//tile_w + y//tile_h) % 2 == 0) else -5)
                r = max(0, min(255, base_color[0] + tint))
                g = max(0, min(255, base_color[1] + tint))
                b = max(0, min(255, base_color[2] + tint))
                rect = pygame.Rect(x+2, y+2, tile_w-3, tile_h-3)
                pygame.draw.rect(bg, (r, g, b), rect, 0)

        # 2) Encimera de madera
        counter_top = wall_height
        counter_height = settings.HEIGHT - counter_top
        wood_base = (133, 94, 66)
        wood_dark = (99, 67, 47)
        wood_light = (160, 120, 85)
        pygame.draw.rect(bg, wood_base, (0, counter_top, settings.WIDTH, counter_height))

        # Vetas de la madera: líneas curvas suaves
        veta_surface = pygame.Surface((settings.WIDTH, counter_height), pygame.SRCALPHA)
        for i in range(20):
            color = wood_dark if i % 2 == 0 else wood_light
            alpha = 30 if i % 2 == 0 else 20
            y = int(counter_height * (i+1) / 21)
            strip = pygame.Surface((settings.WIDTH, 3), pygame.SRCALPHA)
            strip.fill((*color, alpha))
            veta_surface.blit(strip, (0, y))
        bg.blit(veta_surface, (0, counter_top))

        # Borde de encimera con sombra
        border = pygame.Surface((settings.WIDTH, 8), pygame.SRCALPHA)
        for i in range(8):
            a = max(0, 120 - i*15)
            pygame.draw.line(border, (0, 0, 0, a), (0, i), (settings.WIDTH, i))
        bg.blit(border, (0, counter_top - 4))

        # Sombras suaves alrededor para dar profundidad
        vignette = pygame.Surface((settings.WIDTH, settings.HEIGHT), pygame.SRCALPHA)
        for i in range(40):
            a = max(0, 6 - i//8)
            pygame.draw.rect(vignette, (0, 0, 0, a), pygame.Rect(i, i, settings.WIDTH-2*i, settings.HEIGHT-2*i), 1)
        bg.blit(vignette, (0, 0))

        dibujar_fondo_cocina._cache = bg

    # Blit desde cache
    surface.blit(dibujar_fondo_cocina._cache, (0, 0))


def dibujar_fondo_pasteleria(surface):
    """Fondo alternativo estilo pastelería: degradado pastel y suelo ajedrezado.
    Incluye chispas (sprinkles) sutiles y cache.
    """
    if not hasattr(dibujar_fondo_pasteleria, "_cache"):
        dibujar_fondo_pasteleria._cache = None

    if dibujar_fondo_pasteleria._cache is None:
        bg = pygame.Surface((settings.WIDTH, settings.HEIGHT), pygame.SRCALPHA)

        # Degradado vertical pastel (rosa a crema)
        top = (255, 204, 213)   # rosa suave
        bottom = (255, 244, 228)  # crema suave
        for y in range(settings.HEIGHT):
            t = y / max(1, settings.HEIGHT-1)
            r = int(top[0] + (bottom[0]-top[0]) * t)
            g = int(top[1] + (bottom[1]-top[1]) * t)
            b = int(top[2] + (bottom[2]-top[2]) * t)
            pygame.draw.line(bg, (r, g, b), (0, y), (settings.WIDTH, y))

        # Sprinkles/chispas
        sprinkle_colors = [
            (255, 105, 180),  # hot pink
            (135, 206, 235),  # sky blue
            (255, 182, 193),  # light pink
            (255, 215, 0),    # gold
            (152, 251, 152),  # pale green
        ]
        sprinkle_surface = pygame.Surface((settings.WIDTH, settings.HEIGHT), pygame.SRCALPHA)
        import random as _rnd
        for _ in range(220):
            color = (*sprinkle_colors[_rnd.randrange(len(sprinkle_colors))], 100)
            x = _rnd.randrange(settings.WIDTH)
            y = _rnd.randrange(int(settings.HEIGHT * 0.6))
            w = _rnd.randrange(8, 16)
            h = 2
            pygame.draw.rect(sprinkle_surface, color, (x, y, w, h), border_radius=2)
        bg.blit(sprinkle_surface, (0, 0))

        # Suelo ajedrezado blanco y negro en la parte inferior
        floor_top = int(settings.HEIGHT * 0.65)
        tile = 48
        for y in range(floor_top, settings.HEIGHT, tile):
            for x in range(0, settings.WIDTH, tile):
                odd = ((x // tile) + ((y - floor_top) // tile)) % 2
                col = (240, 240, 240) if odd == 0 else (40, 40, 40)
                pygame.draw.rect(bg, col, (x, y, tile, tile))

        # Sombra separando pared y suelo
        shadow = pygame.Surface((settings.WIDTH, 10), pygame.SRCALPHA)
        for i in range(10):
            a = max(0, 120 - i*12)
            pygame.draw.line(shadow, (0, 0, 0, a), (0, i), (settings.WIDTH, i))
        bg.blit(shadow, (0, floor_top - 5))

        dibujar_fondo_pasteleria._cache = bg

    surface.blit(dibujar_fondo_pasteleria._cache, (0, 0))


def ejecutar_juego():
    """Función principal que ejecuta el bucle del juego"""
    # Inicializar sistema gráfico
    screen = inicializar_pygame()
    
    # Crear instancia del juego
    juego = Juego(settings.WIDTH, settings.HEIGHT)
    
    # Configurar reloj para 60 FPS
    clock = pygame.time.Clock()
    
    # Bucle principal del juego
    ejecutando = True
    # Estado: estilo de fondo ("cocina" | "pasteleria")
    estilo_fondo = "cocina"
    while ejecutando:
        # Procesar eventos
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                ejecutando = False
            elif event.type == pygame.KEYDOWN and event.key == pygame.K_b:
                # Toggle de estilo con la tecla B
                estilo_fondo = "pasteleria" if estilo_fondo == "cocina" else "cocina"
            juego.handle_event(event)
        
        # Actualizar lógica del juego
        juego.update()
        
        # Dibujar todo en pantalla
        if estilo_fondo == "cocina":
            dibujar_fondo_cocina(screen)
        else:
            dibujar_fondo_pasteleria(screen)
        juego.draw(screen)
        
        # Actualizar pantalla
        pygame.display.flip()
        clock.tick(60)  # 60 FPS
    
    # Limpiar y cerrar
    pygame.quit()
    sys.exit()


if __name__ == "__main__":
    print("=== INICIANDO COOKIE CLICKER ===")
    print("Layout: Galleta (izq) | Tienda (centro) | Usuario (der)")
    print("=====================================")
    ejecutar_juego()