from django.contrib.auth.backends import ModelBackend
from Aplicaciones.Entrenamientos.models import Usuario

class CorreoBackend(ModelBackend):
    def authenticate(self, request, correo_usu=None, password=None, **kwargs):
        try:
            user = Usuario.objects.get(correo_usu=correo_usu)
            if user.check_password(password):
                return user
        except Usuario.DoesNotExist:
            return None
