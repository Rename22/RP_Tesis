# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#   * Rearrange models' order
#   * Make sure each model has one field with primary_key=True
#   * Make sure each ForeignKey and OneToOneField has `on_delete` set to the desired behavior
#   * Remove `managed = False` lines if you wish to allow Django to create, modify, and delete the table
# Feel free to rename the models, but don't rename db_table values or field names.
from django.db import models


class EntrenamientosCategoria(models.Model):
    id = models.BigAutoField(primary_key=True)
    nombre_cat = models.CharField(max_length=50, blank=True, null=True)
    fecha_creacion_cat = models.DateTimeField()
    fecha_actualizacion_cat = models.DateTimeField()
    descripcion_cat = models.TextField(blank=True, null=True)
    estado_cat = models.CharField(max_length=10)

    class Meta:
        managed = False
        db_table = 'Entrenamientos_categoria'


class EntrenamientosDetalleprueba(models.Model):
    id = models.BigAutoField(primary_key=True)
    titulo_det = models.CharField(max_length=100, blank=True, null=True)
    valoracion_det = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    fecha_creacion_det = models.DateTimeField()
    fecha_actualizacion_det = models.DateTimeField()
    fk_id_pru = models.ForeignKey('EntrenamientosPrueba', models.DO_NOTHING, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'Entrenamientos_detalleprueba'


class EntrenamientosEntrenador(models.Model):
    id = models.BigAutoField(primary_key=True)
    fecha_creacion_ent = models.DateTimeField()
    fecha_actualizacion_ent = models.DateTimeField()
    fk_id_usu = models.ForeignKey('EntrenamientosUsuario', models.DO_NOTHING, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'Entrenamientos_entrenador'


class EntrenamientosEquipo(models.Model):
    id = models.BigAutoField(primary_key=True)
    nombre_equ = models.CharField(max_length=100, blank=True, null=True)
    descripcion_equ = models.TextField(blank=True, null=True)
    logo_equ = models.CharField(max_length=100, blank=True, null=True)
    fecha_fundado_equ = models.DateField(blank=True, null=True)
    fecha_creacion_equ = models.DateTimeField()
    fecha_actualizacion_equ = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'Entrenamientos_equipo'





class EntrenamientosEvaluacion(models.Model):
    id = models.BigAutoField(primary_key=True)
    nombre_eva = models.CharField(max_length=100, blank=True, null=True)
    descripcion_eva = models.TextField(blank=True, null=True)
    fecha_creacion_eva = models.DateTimeField()
    fecha_actualizacion_eva = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'Entrenamientos_evaluacion'


class EntrenamientosJugador(models.Model):
    id = models.BigAutoField(primary_key=True)
    nombre_jug = models.CharField(max_length=100, blank=True, null=True)
    primer_apellido_jug = models.CharField(max_length=100, blank=True, null=True)
    segundo_apellido_jug = models.CharField(max_length=100, blank=True, null=True)
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
    fecha_creacion_jug = models.DateTimeField()
    fecha_actualizacion_jug = models.DateTimeField()
    fk_id_cat = models.ForeignKey(EntrenamientosCategoria, models.DO_NOTHING, blank=True, null=True)
    fk_id_ent = models.ForeignKey(EntrenamientosEntrenador, models.DO_NOTHING, blank=True, null=True)
    fk_id_equ = models.ForeignKey(EntrenamientosEquipo, models.DO_NOTHING, blank=True, null=True)
    fk_id_usu = models.OneToOneField('EntrenamientosUsuario', models.DO_NOTHING, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'Entrenamientos_jugador'


class EntrenamientosPrueba(models.Model):
    id = models.BigAutoField(primary_key=True)
    macro_pru = models.CharField(max_length=10, blank=True, null=True)
    observaciones_pru = models.TextField(blank=True, null=True)
    fecha_pru = models.DateField(blank=True, null=True)
    fecha_creacion_pru = models.DateTimeField()
    fecha_actualizacion_pru = models.DateTimeField()
    fk_id_ent = models.ForeignKey(EntrenamientosEntrenador, models.DO_NOTHING, blank=True, null=True)
    fk_id_eva = models.ForeignKey(EntrenamientosEvaluacion, models.DO_NOTHING, blank=True, null=True)
    fk_id_jug = models.ForeignKey(EntrenamientosJugador, models.DO_NOTHING, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'Entrenamientos_prueba'


class EntrenamientosResultadomacro(models.Model):
    id = models.BigAutoField(primary_key=True)
    macro_resul = models.CharField(max_length=10, blank=True, null=True)
    habilidad_balon_resul = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    defensa_resul = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    mental_resul = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    pase_resul = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    promedio_general = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    fecha_creacion_resul = models.DateTimeField()
    fecha_actualizacion_resul = models.DateTimeField()
    fk_id_jug = models.ForeignKey(EntrenamientosJugador, models.DO_NOTHING, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'Entrenamientos_resultadomacro'
        unique_together = (('fk_id_jug', 'macro_resul'),)


class EntrenamientosTemporada(models.Model):
    id = models.BigAutoField(primary_key=True)
    fecha_inicio_temp = models.DateField(blank=True, null=True)
    fecha_fin_temp = models.DateField(blank=True, null=True)
    fecha_creacion_temp = models.DateTimeField()
    fecha_actualizacion_temp = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'Entrenamientos_temporada'


class EntrenamientosTokenpassword(models.Model):
    id = models.BigAutoField(primary_key=True)
    token = models.CharField(max_length=255, blank=True, null=True)
    expiracion_tok = models.DateTimeField(blank=True, null=True)
    usado_tok = models.BooleanField()
    fecha_creacion_tok = models.DateTimeField()
    fecha_actualizacion_tok = models.DateTimeField()
    fk_id_usu = models.ForeignKey('EntrenamientosUsuario', models.DO_NOTHING, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'Entrenamientos_tokenpassword'


class EntrenamientosUsuario(models.Model):
    id_usu = models.AutoField(primary_key=True)
    correo_usu = models.CharField(unique=True, max_length=150)
    cedula_usu = models.CharField(unique=True, max_length=15)
    primer_apellido_usu = models.CharField(max_length=100, blank=True, null=True)
    segundo_apellido_usu = models.CharField(max_length=100, blank=True, null=True)
    nombres_usu = models.CharField(max_length=100, blank=True, null=True)
    direccion_usu = models.TextField(blank=True, null=True)
    rol_usu = models.CharField(max_length=20)
    password = models.CharField(max_length=255)
    is_active = models.BooleanField()
    is_staff = models.BooleanField()
    is_superuser = models.BooleanField()
    last_login = models.DateTimeField(blank=True, null=True)
    fecha_creacion_usu = models.DateTimeField()
    fecha_actualizacion_usu = models.DateTimeField()
    estado_invitacion = models.CharField(max_length=10)
    estado_usu = models.CharField(max_length=10)
    telefono_usu = models.CharField(max_length=20, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'Entrenamientos_usuario'


class EntrenamientosUsuarioGroups(models.Model):
    id = models.BigAutoField(primary_key=True)
    usuario = models.ForeignKey(EntrenamientosUsuario, models.DO_NOTHING)
    group = models.ForeignKey('AuthGroup', models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'Entrenamientos_usuario_groups'
        unique_together = (('usuario', 'group'),)


class EntrenamientosUsuarioUserPermissions(models.Model):
    id = models.BigAutoField(primary_key=True)
    usuario = models.ForeignKey(EntrenamientosUsuario, models.DO_NOTHING)
    permission = models.ForeignKey('AuthPermission', models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'Entrenamientos_usuario_user_permissions'
        unique_together = (('usuario', 'permission'),)


class AuthGroup(models.Model):
    name = models.CharField(unique=True, max_length=150)

    class Meta:
        managed = False
        db_table = 'auth_group'


class AuthGroupPermissions(models.Model):
    id = models.BigAutoField(primary_key=True)
    group = models.ForeignKey(AuthGroup, models.DO_NOTHING)
    permission = models.ForeignKey('AuthPermission', models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'auth_group_permissions'
        unique_together = (('group', 'permission'),)


class AuthPermission(models.Model):
    name = models.CharField(max_length=255)
    content_type = models.ForeignKey('DjangoContentType', models.DO_NOTHING)
    codename = models.CharField(max_length=100)

    class Meta:
        managed = False
        db_table = 'auth_permission'
        unique_together = (('content_type', 'codename'),)


class DjangoAdminLog(models.Model):
    action_time = models.DateTimeField()
    object_id = models.TextField(blank=True, null=True)
    object_repr = models.CharField(max_length=200)
    action_flag = models.SmallIntegerField()
    change_message = models.TextField()
    content_type = models.ForeignKey('DjangoContentType', models.DO_NOTHING, blank=True, null=True)
    user = models.ForeignKey(EntrenamientosUsuario, models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'django_admin_log'


class DjangoContentType(models.Model):
    app_label = models.CharField(max_length=100)
    model = models.CharField(max_length=100)

    class Meta:
        managed = False
        db_table = 'django_content_type'
        unique_together = (('app_label', 'model'),)


class DjangoMigrations(models.Model):
    id = models.BigAutoField(primary_key=True)
    app = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    applied = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'django_migrations'


class DjangoSession(models.Model):
    session_key = models.CharField(primary_key=True, max_length=40)
    session_data = models.TextField()
    expire_date = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'django_session'
