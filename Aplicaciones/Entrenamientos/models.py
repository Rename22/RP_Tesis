from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

class UsuarioManager(BaseUserManager):
    def create_user(self, correo_usu, cedula_usu, password=None, **extra_fields):
        if not correo_usu:
            raise ValueError('El correo es obligatorio')
        correo_usu = self.normalize_email(correo_usu)
        user = self.model(correo_usu=correo_usu, cedula_usu=cedula_usu, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, correo_usu, cedula_usu, password=None, **extra_fields):
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_staff', True)
        return self.create_user(correo_usu, cedula_usu, password, **extra_fields)

class Usuario(AbstractBaseUser, PermissionsMixin):
    id_usu = models.AutoField(primary_key=True)
    correo_usu = models.CharField(unique=True, max_length=150)
    cedula_usu = models.CharField(unique=True, max_length=15)
    telefono_usu = models.CharField(max_length=20, blank=True, null=True)
    primer_apellido_usu = models.CharField(max_length=100, blank=True, null=True)
    segundo_apellido_usu = models.CharField(max_length=100, blank=True, null=True)
    nombres_usu = models.CharField(max_length=100, blank=True, null=True)
    direccion_usu = models.TextField(blank=True, null=True)

    ESTADOS_INVITACION = [
        ('pendiente', 'Pendiente'),
        ('activado', 'Activado'),
    ]
    estado_invitacion = models.CharField(max_length=10, choices=ESTADOS_INVITACION, default='pendiente')

    ESTADO_USUARIO = [
        ('activo', 'Activo'),
        ('inactivo', 'Inactivo'),
    ]
    estado_usu = models.CharField(max_length=10, choices=ESTADO_USUARIO, default='activo')

    rol_usu = models.CharField(max_length=20, choices=[
        ('admin_dios', 'Admin Dios'),
        ('admin', 'Administrador'),
        ('entrenador', 'Entrenador'),
        ('jugador', 'Jugador'),
    ])

    password = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    last_login = models.DateTimeField(blank=True, null=True)
    fecha_creacion_usu = models.DateTimeField(auto_now_add=True)
    fecha_actualizacion_usu = models.DateTimeField(blank=True, null=True)

    USERNAME_FIELD = 'correo_usu'
    REQUIRED_FIELDS = ['cedula_usu']

    objects = UsuarioManager()

    def __str__(self):
        return f"{self.nombres_usu or ''} {self.primer_apellido_usu or ''}"


class Temporada(models.Model):
    fecha_inicio_temp = models.DateField(blank=True, null=True)
    fecha_fin_temp = models.DateField(blank=True, null=True)
    fecha_creacion_temp = models.DateTimeField(auto_now_add=True)
    fecha_actualizacion_temp = models.DateTimeField(blank=True, null=True)

class Categoria(models.Model):
    nombre_cat = models.CharField(max_length=50, blank=True, null=True)
    descripcion_cat = models.TextField(blank=True, null=True)  # Descripción de la categoría
    ESTADOS_CAT = [
        ('activo', 'Activo'),
        ('inactivo', 'Inactivo'),
    ]
    estado_cat = models.CharField(max_length=10, choices=ESTADOS_CAT, default='activo')
    fecha_creacion_cat = models.DateTimeField(auto_now_add=True)  
    fecha_actualizacion_cat = models.DateTimeField( blank=True, null=True) 

class Equipo(models.Model):
    nombre_equ = models.CharField(max_length=100, blank=True, null=True)
    descripcion_equ = models.TextField(blank=True, null=True)
    logo_equ = models.ImageField(upload_to='equipos/', blank=True, null=True)
    fecha_fundado_equ = models.DateField(blank=True, null=True)
    fecha_creacion_equ = models.DateTimeField(auto_now_add=True)
    fecha_actualizacion_equ = models.DateTimeField(blank=True, null=True)

    categorias = models.ManyToManyField('Categoria', blank=True)








class Entrenador(models.Model):
    fk_id_usu = models.ForeignKey(Usuario, on_delete=models.RESTRICT, blank=True, null=True, related_name='entrenador' )
    fecha_creacion_ent = models.DateTimeField(auto_now_add=True)
    fecha_actualizacion_ent = models.DateTimeField(blank=True, null=True)

class Jugador(models.Model):
    fk_id_usu = models.OneToOneField(Usuario, on_delete=models.RESTRICT, blank=True, null=True)
    fecha_nacimiento_jug = models.DateField(blank=True, null=True)
    edad_jug = models.IntegerField(blank=True, null=True)
    numero_jug = models.IntegerField(blank=True, null=True)
    peso_jug = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    altura_jug = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    posicion_jug = models.CharField(max_length=50, blank=True, null=True)
    pie_dominante_jug = models.CharField(max_length=10, blank=True, null=True)
    nombre_representante_jug = models.CharField(max_length=100, blank=True, null=True)
    numero_emergencia_jug = models.CharField(max_length=15, blank=True, null=True)
    fecha_ingreso_jug = models.DateField(blank=True, null=True)
    fk_id_equ = models.ForeignKey(Equipo, on_delete=models.RESTRICT, blank=True, null=True)
    fk_id_cat = models.ForeignKey(Categoria, on_delete=models.RESTRICT, blank=True, null=True)
    fk_id_ent = models.ForeignKey(Entrenador, on_delete=models.RESTRICT, blank=True, null=True)
    fecha_creacion_jug = models.DateTimeField(auto_now_add=True)
    fecha_actualizacion_jug = models.DateTimeField(blank=True, null=True)

class TipoEvaluacion(models.Model):
    nombre_tip = models.CharField(max_length=100, blank=True, null=True)  # Nombre del tipo de evaluación (Ej. Física, Táctica)
    descripcion_tip = models.TextField(blank=True, null=True)  # Descripción del tipo de evaluación
    estado_tip = models.BooleanField(default=True)  # Estado booleano para activar/desactivar la evaluación
    fecha_creacion_tip = models.DateTimeField(auto_now_add=True)  # Fecha de creación
    fecha_actualizacion_tip = models.DateTimeField(blank=True, null=True)  # Fecha de actualización

    
class ParametroEvaluacion(models.Model):
    nombre_prm = models.CharField(max_length=100, blank=True, null=True)  # Nombre del parámetro de evaluación (Ej. Control de balón)
    descripcion_prm = models.TextField(blank=True, null=True)  # Descripción del parámetro
    fk_tipo_evaluacion = models.ForeignKey(TipoEvaluacion, on_delete=models.CASCADE)  # Relación con TipoEvaluacion
    estado_prm = models.BooleanField(default=True)  # Estado booleano para activar/desactivar el parámetro
    fecha_creacion_prm = models.DateTimeField(auto_now_add=True)  # Fecha de creación
    fecha_actualizacion_prm = models.DateTimeField(blank=True, null=True)  # Fecha de actualización




class Prueba(models.Model):
    fk_id_ent = models.ForeignKey(Entrenador, on_delete=models.RESTRICT, blank=True, null=True)
    fk_id_jug = models.ForeignKey(Jugador, on_delete=models.RESTRICT, blank=True, null=True)
    fk_id_tip = models.ForeignKey(TipoEvaluacion, on_delete=models.RESTRICT, blank=True, null=True)
    macro_pru = models.CharField(max_length=10, blank=True, null=True)
    observaciones_pru = models.TextField(blank=True, null=True)
    fecha_pru = models.DateField(blank=True, null=True)
    fecha_creacion_pru = models.DateTimeField(auto_now_add=True)
    fecha_actualizacion_pru = models.DateTimeField(blank=True, null=True)

class DetallePrueba(models.Model):
    fk_id_pru = models.ForeignKey(Prueba, on_delete=models.RESTRICT, blank=True, null=True)
    fk_id_parametro = models.ForeignKey(ParametroEvaluacion, on_delete=models.RESTRICT, blank=True, null=True)  # Relación con los parámetros de evaluación
    valoracion_det = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)  # Valoración para ese parámetro específico
    fecha_creacion_det = models.DateTimeField(auto_now_add=True)
    fecha_actualizacion_det = models.DateTimeField(blank=True, null=True)


class ResultadoMacro(models.Model):
    fk_id_jug = models.ForeignKey(Jugador, on_delete=models.RESTRICT, blank=True, null=True)
    macro_resul = models.CharField(max_length=10, blank=True, null=True)
    habilidad_balon_resul = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    defensa_resul = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    mental_resul = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    pase_resul = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    promedio_general = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    fecha_creacion_resul = models.DateTimeField(auto_now_add=True)
    fecha_actualizacion_resul = models.DateTimeField(blank=True, null=True)

    class Meta:
        unique_together = (('fk_id_jug', 'macro_resul'),)

class TokenPassword(models.Model):
    fk_id_usu = models.ForeignKey(Usuario, on_delete=models.RESTRICT, blank=True, null=True)
    token = models.CharField(max_length=255, blank=True, null=True)
    expiracion_tok = models.DateTimeField(blank=True, null=True)
    usado_tok = models.BooleanField(default=False)
    fecha_creacion_tok = models.DateTimeField(auto_now_add=True)
    fecha_actualizacion_tok = models.DateTimeField(blank=True, null=True)
