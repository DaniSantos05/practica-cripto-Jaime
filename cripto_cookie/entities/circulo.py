import pygame
import os
import random
from core import settings

class Circulo:
    def __init__(self, x, y):
        self.radius = 100
        # Superficie base y rect para colisiones/posicionamiento
        self.image = pygame.Surface((self.radius*2, self.radius*2), pygame.SRCALPHA)
        self.rect = self.image.get_rect(topleft=(x, y))
        
        # Estado de la galleta
        self.scale = 1.0
        self.hover_effect = 0
        
        # Efectos visuales
        self.floating_numbers = []
        
        # Fuentes para números flotantes
        self.font_small = pygame.font.Font(pygame.font.get_default_font(), 16)
        self.font_medium = pygame.font.Font(pygame.font.get_default_font(), 20)

        # Cargar y preparar la imagen de la cookie una sola vez
        assets_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "assets")
        cookie_path = os.path.join(assets_dir, "cookie.png")
        # Guardamos el original para reescalar cada frame según "self.scale"
        # Usamos convert_alpha() para mantener la transparencia de la imagen
        self.cookie_original = pygame.image.load(cookie_path).convert_alpha()
        
    def on_click(self, cookies_gained):
        """Llamar cuando se hace click en la galleta"""
        self.scale = 1.3
        
        # Agregar número flotante
        self.add_floating_number(cookies_gained)
        
    def add_floating_number(self, value):
        """Agregar número flotante que sube"""
        x = self.rect.centerx + random.randint(-40, 40)
        y = self.rect.centery + random.randint(-40,40)
        self.floating_numbers.append({
            "value": value,
            "x": x,
            "y": y,
            "timer": 0,
            "max_time": 60,  # 1 segundo a 60 FPS
            "color": settings.GOLDEN
        })
    
    def update(self):
        """Actualizar efectos visuales (asume 60 FPS)"""
        # Actualizar escala
        if self.scale > 1.0:
            self.scale = max(1.0, self.scale - 0.02)
        
        # Actualizar números flotantes
        for number in self.floating_numbers[:]:
            number["timer"] += 1  # Usar contador de frames
            number["y"] -= 1.5  # Subir
            if number["timer"] > number["max_time"]:
                self.floating_numbers.remove(number)
    
    def draw(self, surface):
        """Dibujar la galleta con efectos sutiles"""
        # Actualizar efectos
        self.update()
        # Dibujar la galleta (estilo Cookie Clicker real)
        # Escalar la imagen de la cookie para que coincida con el círculo y comparta el efecto de click
        # pygame.draw.circle(surface, settings.YELLOW, self.rect.center, self.radius)
        target_diameter = max(1, int(self.radius * 2 * self.scale))
        # Escalado suave manteniendo la relación de aspecto original
        ow, oh = self.cookie_original.get_size()
        if max(ow, oh) <= 0:
            scale_w = scale_h = target_diameter
        else:
            factor = target_diameter / max(ow, oh)
            scale_w = max(1, int(ow * factor))
            scale_h = max(1, int(oh * factor))
        cookie_scaled = pygame.transform.smoothscale(self.cookie_original, (scale_w, scale_h))
        cookie_rect = cookie_scaled.get_rect(center=self.rect.center)
        surface.blit(cookie_scaled, cookie_rect.topleft)
        
        
        # Dibujar números flotantes
        for number in self.floating_numbers:
            alpha = int(255 * (1 - number["timer"] / number["max_time"]))
            if alpha > 0:
                if number["value"] >= 10:
                    font = self.font_medium
                else:
                    font = self.font_small
                text = f"+{number["value"]}"
                if len(number["color"]) == 3:
                    color = (*number["color"], alpha)
                else:
                    color = number["color"]
                text_surface = font.render(text, True, color[:3])
                text_surface.set_alpha(alpha)
                surface.blit(text_surface, (number["x"] - text_surface.get_width()//2, number["y"]))