from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

class UsuarioManager(BaseUserManager):
    def create_user(self, correo_usu, nombres_usu, password=None, **extra_fields):
        if not correo_usu:
            raise ValueError('El correo es obligatorio')
        correo_usu = self.normalize_email(correo_usu)
        user = self.model(correo_usu=correo_usu, nombres_usu=nombres_usu, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, correo_usu, nombres_usu, password=None, **extra_fields):
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('rol_usu', 'admin_dios')

        return self.create_user(correo_usu, nombres_usu, password, **extra_fields)



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
    REQUIRED_FIELDS = ['nombres_usu']

    objects = UsuarioManager()

    def __str__(self):
        return f"{self.nombres_usu or ''} {self.primer_apellido_usu or ''}"


class TokenPassword(models.Model):
    id_tok = models.AutoField(primary_key=True)
    fk_id_usu = models.ForeignKey(Usuario, on_delete=models.CASCADE, blank=True, null=True)
    token = models.CharField(max_length=255, blank=True, null=True)
    expiracion_tok = models.DateTimeField(blank=True, null=True)
    usado_tok = models.BooleanField(default=False)
    fecha_creacion_tok = models.DateTimeField(auto_now_add=True)
    fecha_actualizacion_tok = models.DateTimeField(blank=True, null=True)


class Temporada(models.Model):
    id_temp = models.AutoField(primary_key=True)
    nombre_temp = models.CharField(max_length=100, blank=True, null=True) 
    fecha_inicio_temp = models.DateField(blank=True, null=True)
    fecha_fin_temp = models.DateField(blank=True, null=True)
    fecha_creacion_temp = models.DateTimeField(auto_now_add=True)
    fecha_actualizacion_temp = models.DateTimeField(blank=True, null=True)

class Categoria(models.Model):
    id_cat = models.AutoField(primary_key=True)
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
    id_equ = models.AutoField(primary_key=True)
    nombre_equ = models.CharField(max_length=100, blank=True, null=True)
    descripcion_equ = models.TextField(blank=True, null=True)
    logo_equ = models.ImageField(upload_to='equipos/', blank=True, null=True)
    fecha_fundado_equ = models.DateField(blank=True, null=True)
    fecha_creacion_equ = models.DateTimeField(auto_now_add=True)
    fecha_actualizacion_equ = models.DateTimeField(blank=True, null=True)
    fk_id_temp = models.ForeignKey('Temporada', on_delete=models.SET_NULL, null=True, blank=True)
    fk_id_ent = models.ForeignKey('Entrenador', on_delete=models.SET_NULL, null=True, blank=True)
    categorias = models.ManyToManyField('Categoria', blank=True)








class Entrenador(models.Model):
    id_ent = models.AutoField(primary_key=True)
    fk_id_usu = models.ForeignKey(Usuario, on_delete=models.CASCADE, blank=True, null=True, related_name='entrenador' )
    fecha_creacion_ent = models.DateTimeField(auto_now_add=True)
    fecha_actualizacion_ent = models.DateTimeField(blank=True, null=True)

class Jugador(models.Model):
    id_jug = models.AutoField(primary_key=True)
    fk_id_usu = models.OneToOneField(Usuario, on_delete=models.CASCADE, blank=True, null=True)
    fecha_nacimiento_jug = models.DateField(blank=True, null=True)
    edad_jug = models.IntegerField(blank=True, null=True)
    
    peso_jug = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    altura_jug = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    posicion_jug = models.CharField(max_length=50, blank=True, null=True)
    pie_dominante_jug = models.CharField(max_length=10, blank=True, null=True)
    nombre_representante_jug = models.CharField(max_length=100, blank=True, null=True)
    numero_emergencia_jug = models.CharField(max_length=15, blank=True, null=True)
    fecha_ingreso_jug = models.DateField(blank=True, null=True)
    fk_id_equ = models.ForeignKey(Equipo, on_delete=models.CASCADE, blank=True, null=True)
    fk_id_cat = models.ForeignKey(Categoria, on_delete=models.CASCADE, blank=True, null=True)
    fk_id_ent = models.ForeignKey(Entrenador, on_delete=models.CASCADE, blank=True, null=True)
    fecha_creacion_jug = models.DateTimeField(auto_now_add=True)
    fecha_actualizacion_jug = models.DateTimeField(blank=True, null=True)

class TipoEvaluacion(models.Model):
    id_tip = models.AutoField(primary_key=True)
    nombre_tip = models.CharField(max_length=100, blank=True, null=True)  # Nombre del tipo de evaluación (Ej. Física, Táctica)
    descripcion_tip = models.TextField(blank=True, null=True)  # Descripción del tipo de evaluación
    estado_tip = models.BooleanField(default=True)  # Estado booleano para activar/desactivar la evaluación
    fecha_creacion_tip = models.DateTimeField(auto_now_add=True)  # Fecha de creación
    fecha_actualizacion_tip = models.DateTimeField(blank=True, null=True)  # Fecha de actualización
    cualitativa_tip = models.BooleanField(default=False)

    
class ParametroEvaluacion(models.Model):
    id_prm = models.AutoField(primary_key=True)
    nombre_prm = models.CharField(max_length=100, blank=True, null=True)  # Nombre del parámetro de evaluación (Ej. Control de balón)
    descripcion_prm = models.TextField(blank=True, null=True)  # Descripción del parámetro
    fk_tipo_evaluacion = models.ForeignKey(TipoEvaluacion, on_delete=models.CASCADE)  # Relación con TipoEvaluacion
    estado_prm = models.BooleanField(default=True)  # Estado booleano para activar/desactivar el parámetro
    fecha_creacion_prm = models.DateTimeField(auto_now_add=True)  # Fecha de creación
    fecha_actualizacion_prm = models.DateTimeField(blank=True, null=True)  # Fecha de actualización

class UnidadEscala(models.Model):
    id_unes = models.AutoField(primary_key=True)
    nombre_unes = models.CharField(max_length=50, unique=True)  # Ej: Segundos, Metros, Toques
    descripcion_unes = models.CharField(max_length=100, blank=True, null=True)
    estado_unes = models.BooleanField(default=True)
    fecha_creacion_unes = models.DateTimeField(auto_now_add=True)
    fecha_actualizacion_unes = models.DateTimeField(blank=True, null=True)

class Rubrica(models.Model):
    id_rub = models.AutoField(primary_key=True)
    fk_id_prm = models.ForeignKey(ParametroEvaluacion, on_delete=models.CASCADE)
    fk_id_cat = models.ForeignKey(Categoria, on_delete=models.CASCADE)
    fk_id_unes = models.ForeignKey(UnidadEscala, on_delete=models.CASCADE, null=True, blank=True)
    valor_min_rub = models.DecimalField(max_digits=6, decimal_places=2, null=True, blank=True)     # Ej: 10.00
    valor_max_rub = models.DecimalField(max_digits=6, decimal_places=2, null=True, blank=True)     # Ej: 11.00
    rubrica_cualitativa = models.TextField(null=True, blank=True)
    puntaje_rub = models.DecimalField(max_digits=4, decimal_places=2)       # Ej: 9.5
    estado_rub = models.BooleanField(default=True)
    fecha_creacion_rub = models.DateTimeField(auto_now_add=True)
    fecha_actualizacion_rub = models.DateTimeField(blank=True, null=True)


    
class EscalaEvaluacion(models.Model):
    id_escala = models.AutoField(primary_key=True)
    fk_id_tip = models.ForeignKey(TipoEvaluacion, on_delete=models.CASCADE)      # Tipo de Evaluación
    fk_id_prm = models.ForeignKey(ParametroEvaluacion, on_delete=models.CASCADE) # Parámetro de Evaluación
    fk_id_cat = models.ForeignKey(Categoria, on_delete=models.CASCADE)           # Categoría
    valoroptimo_escala = models.DecimalField(max_digits=5, decimal_places=2)     # Valor óptimo
    tipo_escala = models.CharField(max_length=10, choices=[('inversa', 'Inversa'), ('directa', 'Directa')])
    unidad_escala = models.CharField(max_length=100)                             # Unidad de la escala
    fecha_creacion_escala = models.DateTimeField(auto_now_add=True)
    fecha_actualizacion_escala = models.DateTimeField(blank=True, null=True)



class Prueba(models.Model):
    id_pru = models.AutoField(primary_key=True)
    fk_id_ent = models.ForeignKey('Entrenador', on_delete=models.CASCADE, null=True, blank=True)
    fk_id_jug = models.ForeignKey('Jugador', on_delete=models.CASCADE)
    fk_id_tip = models.ForeignKey('TipoEvaluacion', on_delete=models.CASCADE)
    fk_id_temp = models.ForeignKey('Temporada', on_delete=models.CASCADE)
    fk_id_ciclo = models.ForeignKey('CicloDeEntrenamiento', on_delete=models.CASCADE)
    promedio_pru = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)  # Promedio de esta PRUEBA (en tiempo real)
    observaciones_pru = models.TextField(blank=True, null=True)
    estado_pru = models.BooleanField(default=True)
    fecha_pru = models.DateField(null=True, blank=True)
    fecha_creacion_pru = models.DateTimeField(auto_now_add=True)
    fecha_actualizacion_pru = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = (('fk_id_jug', 'fk_id_tip', 'fk_id_temp', 'fk_id_ciclo'),)

class DetallePrueba(models.Model):
    id_detpru = models.AutoField(primary_key=True)
    fk_id_pru = models.ForeignKey('Prueba', on_delete=models.CASCADE, related_name="detalles")
    fk_id_prm = models.ForeignKey('ParametroEvaluacion', on_delete=models.CASCADE)
    valor_observado = models.TextField(blank=True, null=True)  # Valor que ingresa el entrenador (ej: segundos, metros)
    unidad = models.CharField(max_length=30, blank=True, null=True)                                # Unidad (ej: 'segundos', 'metros')
    nota_calculada = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)   # Nota según la rúbrica
    fecha_creacion_detpru = models.DateTimeField(auto_now_add=True)
    fecha_actualizacion_detpru = models.DateTimeField(null=True, blank=True)



class PromedioJugador(models.Model):
    id_proju = models.AutoField(primary_key=True)
    jugador_proju = models.ForeignKey(Jugador, on_delete=models.CASCADE)
    fk_id_ciclo = models.ForeignKey('CicloDeEntrenamiento', on_delete=models.CASCADE)
    tipo_proju = models.ForeignKey(TipoEvaluacion, on_delete=models.CASCADE)
    temporada_proju = models.ForeignKey(Temporada, on_delete=models.CASCADE)
    promedio_proju = models.DecimalField(max_digits=5, decimal_places=2)
    fecha_calculo_proju = models.DateTimeField(auto_now_add=True)

    

class CicloDeEntrenamiento(models.Model):
    id_ciclo = models.AutoField(primary_key=True)
    nombre_ciclo = models.CharField(max_length=100, blank=True, null=True)  # Nombre del ciclo (Ej. "Macrociclo", "Mesociclo 1", etc.)
    estado_ciclo = models.BooleanField(default=True)  # Estado del ciclo (activo/inactivo)
    fecha_creacion_ciclo = models.DateTimeField(auto_now_add=True)  # Fecha de creación
    fecha_actualizacion_ciclo = models.DateTimeField(blank=True, null=True)  # Fecha de actualización