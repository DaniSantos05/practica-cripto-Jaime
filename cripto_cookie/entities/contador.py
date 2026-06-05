import pygame
from core import settings

class Contador:
    def __init__(self, x, y):
        self.color = settings.PANEL_BROWN
        self.width = 300
        self.height = 160  # Más alto para más información
        self.image = pygame.Surface((self.width, self.height))
        self.rect = self.image.get_rect(topleft=(x, y))
        self.image.fill(self.color)
        self.font_titulo = pygame.font.Font(pygame.font.get_default_font(), 22)
        self.font_grande = pygame.font.Font(pygame.font.get_default_font(), 28)
        self.font_pequeno = pygame.font.Font(pygame.font.get_default_font(), 16)
        self.font_mini = pygame.font.Font(pygame.font.get_default_font(), 14)
        self.cookies = 0
        self.cookies_por_segundo = 0
        self.cookies_por_click = 1
        
    def añadir_cookies(self, cantidad):
        """Añadir cookies al contador"""
        self.cookies += cantidad
        
    def reiniciar(self):
        """Reiniciar el contador a estado inicial (para logout)"""
        self.cookies = 0
        self.cookies_por_segundo = 0
        self.cookies_por_click = 1
        
    def draw(self, surface):
        # Generar el panel con estilo Cookie Clicker
        pygame.draw.rect(surface, self.color, self.rect)
        pygame.draw.rect(surface, settings.GOLDEN, self.rect, 3)
        
        # Título
        titulo_surf = self.font_titulo.render("ESTADÍSTICAS", True, settings.TEXT_CREAM)
        titulo_rect = titulo_surf.get_rect(centerx=self.rect.centerx, y=self.rect.y + 10)
        surface.blit(titulo_surf, titulo_rect)
        
        # Cantidad de cookies (número grande)
        cookies_text = f"{self.cookies:,}"
        
        # Verificar si necesita formato abreviado
        es_millon = False
        es_mil = False
        
        if self.cookies >= 1000000:
            es_millon = True
        elif self.cookies >= 1000:
            es_mil = True
        
        if es_millon:
            cookies_text = f"{self.cookies/1000000:.1f}M"
        elif es_mil:
            cookies_text = f"{self.cookies/1000:.1f}K"
            
        cookies_surf = self.font_grande.render(cookies_text, True, settings.GOLDEN)
        cookies_rect = cookies_surf.get_rect(centerx=self.rect.centerx, y=self.rect.y + 40)
        surface.blit(cookies_surf, cookies_rect)
        
        # Etiqueta "cookies"
        label_surf = self.font_pequeno.render("cookies", True, settings.CREAM)
        label_rect = label_surf.get_rect(centerx=self.rect.centerx, y=self.rect.y + 75)
        surface.blit(label_surf, label_rect)
        
        # Cookies por click
        cpc_surf = self.font_pequeno.render(f"{self.cookies_por_click}/click", True, settings.ACCENT_GOLD)
        cpc_rect = cpc_surf.get_rect(centerx=self.rect.centerx, y=self.rect.y + 100)
        surface.blit(cpc_surf, cpc_rect)
        
        # Cookies por segundo
        tiene_auto_clicks = False
        if self.cookies_por_segundo > 0:
            tiene_auto_clicks = True
        
        if tiene_auto_clicks:
            cps_color = settings.ACCENT_GOLD
        else:
            cps_color = settings.GRAY
        
        cps_surf = self.font_pequeno.render(f"{self.cookies_por_segundo}/seg", True, cps_color)
        cps_rect = cps_surf.get_rect(centerx=self.rect.centerx, y=self.rect.y + 125)
        surface.blit(cps_surf, cps_rect)
        
        # Instrucción basada en estado de auto-clicks
        sin_auto_clicks = False
        if self.cookies_por_segundo == 0:
            sin_auto_clicks = True
        
        if sin_auto_clicks:
            instruccion_text = "¡Haz click en la galleta!"
        else:
            instruccion_text = "¡Auto-generando cookies!"
            
        instruccion_surf = self.font_mini.render(instruccion_text, True, settings.CREAM)
        instruccion_rect = instruccion_surf.get_rect(centerx=self.rect.centerx, y=self.rect.y + 145)
        surface.blit(instruccion_surf, instruccion_rect)