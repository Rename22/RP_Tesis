from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.views.generic import View
from django.contrib.auth.decorators import login_required
from django.utils.crypto import get_random_string
from django.core.mail import EmailMessage
from django.urls import reverse
from django.db.models import ProtectedError
from django.contrib import messages
from .models import Usuario, TokenPassword, Categoria, Temporada, Equipo, Entrenador, Jugador, TipoEvaluacion, ParametroEvaluacion, Prueba, DetallePrueba
from django.utils import timezone
from django.db.models import Q
import pytz
import uuid
from django.views.decorators.http import require_GET
from django.http import JsonResponse
def index(request):
    return render(request, 'index.html')

class CustomLoginView(View):
    def get(self, request):
        return render(request, 'registration/login.html')

    def post(self, request):
        correo = request.POST.get('correo_usu')
        password = request.POST.get('password')

        user = authenticate(request, correo_usu=correo, password=password)

        if user is not None:
            login(request, user)
            next_url = request.GET.get('next') or '/admin-dashboard/'
            return redirect(next_url)
        else:
            messages.error(request, "Correo o contraseña incorrectos.")
            return redirect('login')

def CustomLogoutView(request):
    logout(request)
    return redirect('index')

#VALIDACION EN BDD


@require_GET
def validate_cedula(request):
    cedula = request.GET.get('cedula_usu')
    exclude_id = request.GET.get('exclude_id')

    qs = Usuario.objects.filter(cedula_usu=cedula)
    if exclude_id:
        try:
            qs = qs.exclude(pk=int(exclude_id))
        except (TypeError, ValueError):
            pass

    existe = qs.exists()
    return JsonResponse(not existe, safe=False)

@require_GET
def validate_correo(request):
    correo = request.GET.get('correo_usu')
    exclude_id = request.GET.get('exclude_id')

    qs = Usuario.objects.filter(correo_usu=correo)
    if exclude_id:
        try:
            qs = qs.exclude(pk=int(exclude_id))
        except (TypeError, ValueError):
            pass

    existe = qs.exists()
    return JsonResponse(not existe, safe=False)

# -------------------------------MENU PRINCIPAL ----------------------------
@login_required
def admin_dashboard(request):
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.warning(request, "No tienes permiso para acceder aquí.")
        return redirect('login')

    context = {
        'rol_usuario': request.user.rol_usu,
        'usuario': request.user  # aquí pasas el usuario completo para poder acceder al nombre
    }
    return render(request, 'admin_dashboard.html', context)

# -------------------------------MANEJO DE TOKENS-----------------------------
def crear_contrasena(request, token):
    if request.user.is_authenticated:
        return redirect('admin_dashboard')

    try:
        tp = TokenPassword.objects.get(token=token, usado_tok=False)
    except TokenPassword.DoesNotExist:
        messages.error(request, "Enlace inválido o ya usado.")
        return redirect('login')

    if request.method == 'POST':
        p1 = request.POST.get('password')
        p2 = request.POST.get('confirmar')
        if not p1 or p1 != p2:
            messages.error(request, "Las contraseñas deben coincidir.")
        else:
            user = tp.fk_id_usu
            user.set_password(p1)
            user.is_active = True
            user.estado_invitacion = 'ACEPTADA'  # ✅ Se actualiza el estado de invitación
            user.save()
            tp.usado_tok = True
            tp.fecha_actualizacion_tok = timezone.now()
            tp.save()
            messages.success(request, "Contraseña creada. Ya puedes iniciar sesión.")
            return redirect('login')

    return render(request, 'crear_contrasena.html', {'token': token})


# Restablecer contraseña
def password_reset_confirm(request, token):
    guayaquil_tz = pytz.timezone('America/Guayaquil')

    now_utc = timezone.now()

    tp = TokenPassword.objects.filter(
        token=token,
        usado_tok=False
    ).filter(
        Q(expiracion_tok__isnull=True) | Q(expiracion_tok__gte=now_utc)
    ).first()

    if tp is None:
        messages.error(request, "El enlace es inválido o ha expirado.")
        return render(request, 'registration/login.html')

    if request.method == "POST":
        p1 = request.POST.get("password")
        p2 = request.POST.get("confirmar")

        if not p1 or p1 != p2:
            messages.error(request, "Las contraseñas deben coincidir.")
        else:
            user = tp.fk_id_usu
            user.set_password(p1)
            user.save()
            tp.usado_tok = True
            tp.fecha_actualizacion_tok = timezone.now()
            tp.save()
            messages.success(request, "Contraseña actualizada correctamente.")
            return redirect('login')

    return render(request, 'crear_contrasena.html', {'token': token})


# Recuperar contraseña
def password_reset_request(request):
    if request.method == "POST":
        email = request.POST.get("email")
        try:
            user = Usuario.objects.get(correo_usu=email)
        except Usuario.DoesNotExist:
            messages.error(request, "No existe un usuario con ese correo.")
            return redirect('password_reset_request')
        
        # Invalidar tokens anteriores no usados
        TokenPassword.objects.filter(fk_id_usu=user, usado_tok=False).update(usado_tok=True)

        # Crear token
        token = str(uuid.uuid4())
        expiration = timezone.now() + timezone.timedelta(hours=1)  # 1 hora de validez

        tp = TokenPassword.objects.create(
            token=token,
            usado_tok=False,
            fk_id_usu=user,
            expiracion_tok=expiration,
            fecha_creacion_tok=timezone.now(),
            fecha_actualizacion_tok=None
        )

        # Construir link
        reset_link = request.build_absolute_uri(reverse('password_reset_confirm', args=[token]))

        # Cuerpo HTML del correo
        cuerpo = f"""
        <div style="font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 30px;">
            <div style="max-width: 600px; margin: auto; background: #fff; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); padding: 40px;">
                <h2 style="color: #333;">Hola, {user.nombres_usu}!</h2>
                <p style="font-size: 16px; color: #555;">
                    Has solicitado restablecer tu contraseña. Haz clic en el botón de abajo para continuar:
                </p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{reset_link}" style="
                        background-color: #007bff;
                        color: #fff;
                        padding: 12px 25px;
                        font-size: 16px;
                        border-radius: 5px;
                        text-decoration: none;
                        font-weight: bold;
                        display: inline-block;">
                        Restablecer Contraseña
                    </a>
                </div>
                <p style="font-size: 14px; color: #999;">
                    Si no solicitaste este correo, puedes ignorarlo.
                </p>
                <hr style="margin-top: 40px; border: none; border-top: 1px solid #eee;">
                <p style="text-align: center; color: #ccc; font-size: 12px;">
                    © 2025 Sistema de Entrenamientos
                </p>
            </div>
        </div>
        """

        email_msg = EmailMessage(
            subject="Recuperación de contraseña - Sistema Entrenamientos",
            body=cuerpo,
            from_email="noreply@tusistema.com",
            to=[email]
        )
        email_msg.content_subtype = "html"  # Para indicar que es HTML
        email_msg.send(fail_silently=False)

        messages.success(request, "Se ha enviado un correo con instrucciones para recuperar tu contraseña.")
        return redirect('login')

    return render(request, 'registration/password_reset_request.html')


# -------------------------------CRUD ADMINISTRADORES ----------------------------
# Listar administradores
@login_required
def list_admins(request):
    if request.user.rol_usu != 'admin_dios':
        messages.warning(request, "No tienes permiso para acceder aquí.")
        return redirect('admin_dashboard')

    admins = Usuario.objects.filter(rol_usu='admin')
    return render(request, 'Admin/listAdmin.html', {'admins': admins})

# Crear administrador
@login_required
def add_admin(request):
    if request.user.rol_usu != 'admin_dios':
        messages.error(request, "No tienes permiso para crear administradores.")
        return redirect('admin_dashboard')

    if request.method == 'POST':
        correo     = request.POST['correo_usu']
        cedula     = request.POST['cedula_usu']
        telefono   = request.POST['telefono_usu']
        nombres    = request.POST['nombres_usu']
        p_apellido = request.POST['primer_apellido_usu']
        s_apellido = request.POST['segundo_apellido_usu']
        direccion  = request.POST['direccion_usu']
        fecha_creacion_usu = timezone.now()
        fecha_actualizacion_usu = None

        usuario = Usuario(
            correo_usu=correo,
            cedula_usu=cedula,
            telefono_usu=telefono,
            nombres_usu=nombres,
            primer_apellido_usu=p_apellido,
            segundo_apellido_usu=s_apellido,
            direccion_usu=direccion,
            rol_usu='admin',
            estado_invitacion='pendiente',
            estado_usu='activo',
            is_active=True,
            is_staff=True,
            fecha_creacion_usu=timezone.now(),
            fecha_actualizacion_usu=None,
        )
        usuario.set_unusable_password()
        usuario.save()

        token = get_random_string(64)
        TokenPassword.objects.create(
            fk_id_usu=usuario,
            token=token,
            usado_tok=False,
            fecha_creacion_tok=timezone.now(),
            fecha_actualizacion_tok=None,
        )

        enlace = request.build_absolute_uri(reverse('activar_contrasena', args=[token]))

        cuerpo = f"""
        <div style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 30px;">
            <div style="max-width: 600px; margin: auto; background: #fff; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); padding: 40px;">
                <h2 style="color: #333;">¡Hola, {nombres}!</h2>
                <p style="font-size: 16px; color: #555;">
                    Has sido registrado como <strong>Administrador</strong> en el Sistema de Entrenamientos.
                </p>
                <p style="font-size: 16px; color: #555;">
                    Para activar tu cuenta y establecer una contraseña, haz clic en el siguiente botón:
                </p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{enlace}" style="
                        background-color: #28a745;
                        color: #fff;
                        text-decoration: none;
                        padding: 12px 24px;
                        font-size: 16px;
                        border-radius: 5px;
                        display: inline-block;
                        font-weight: bold;">
                        Activar Cuenta
                    </a>
                </div>
                <p style="font-size: 14px; color: #999;">
                    Si no solicitaste este acceso, puedes ignorar este correo.
                </p>
                <hr style="margin-top: 40px; border: none; border-top: 1px solid #eee;">
                <p style="text-align: center; color: #ccc; font-size: 12px;">
                    © 2025 Sistema de Administración de Entrenamientos
                </p>
            </div>
        </div>
        """

        email = EmailMessage(
            subject="Crea tu contraseña de Administrador",
            body=cuerpo,
            to=[correo],
        )
        email.content_subtype = "html"
        email.send(fail_silently=True)

        messages.success(request, f"Invitación enviada a {correo}.")

    return redirect('list_admins')




# Editar administrador
@login_required
def edit_admin(request, pk):
    if request.user.rol_usu != 'admin_dios':
        messages.error(request, "No tienes permiso para editar administradores.")
        return redirect('list_admins')

    admin = get_object_or_404(Usuario, pk=pk, rol_usu='admin')

    if request.method == 'POST':
        admin.correo_usu = request.POST['correo_usu']
        admin.cedula_usu = request.POST['cedula_usu']
        admin.telefono_usu = request.POST['telefono_usu']
        admin.nombres_usu = request.POST['nombres_usu']
        admin.primer_apellido_usu = request.POST['primer_apellido_usu']
        admin.segundo_apellido_usu = request.POST['segundo_apellido_usu']
        admin.direccion_usu = request.POST['direccion_usu']
        admin.estado_usu = request.POST['estado_usu'].lower()  
        admin.fecha_actualizacion_usu = timezone.now()
        admin.save()

        messages.success(request, "Administrador actualizado correctamente.")

    return redirect('list_admins')

# Eliminar administrador
@login_required
def delete_admin(request, pk):
    if request.user.rol_usu != 'admin_dios':
        messages.error(request, "No tienes permiso para esta acción.")
        return redirect('list_admins')

    if request.method == 'POST':
        password = request.POST.get('confirm_password')

        if not request.user.check_password(password):
            messages.error(request, "Contraseña incorrecta. No se pudo eliminar.")
            return redirect('list_admins')

        try:
            u = get_object_or_404(Usuario, pk=pk, rol_usu='admin')
            TokenPassword.objects.filter(fk_id_usu=u).delete()
            u.delete()
            messages.success(request, "Administrador eliminado correctamente.")
        except ProtectedError:
            messages.error(request, "No se puede eliminar este administrador porque tiene registros protegidos.")
        except Exception as e:
            messages.error(request, f"Ocurrió un error inesperado: {e}")

    return redirect('list_admins')






# -------------------------------CRUD ENTRENADORES ----------------------------

@login_required
def list_entrenadores(request):
    if request.user.rol_usu not in ['admin_dios', 'admin']:
        messages.warning(request, "No tienes permiso para acceder aquí.")
        return redirect('admin_dashboard')

    entrenadores = Entrenador.objects.select_related('fk_id_usu').all()
    return render(request, 'Entrenador/listEntrenador.html', {'entrenadores': entrenadores})


@login_required
def add_entrenador(request):
    if request.user.rol_usu not in ['admin_dios', 'admin']:
        messages.error(request, "No tienes permiso para crear entrenadores.")
        return redirect('admin_dashboard')

    if request.method == 'POST':
        correo     = request.POST['correo_usu']
        cedula     = request.POST['cedula_usu']
        telefono   = request.POST['telefono_usu']
        nombres    = request.POST['nombres_usu']
        p_apellido = request.POST['primer_apellido_usu']
        s_apellido = request.POST['segundo_apellido_usu']
        direccion  = request.POST['direccion_usu']
        fecha_creacion_usu = timezone.now()
        fecha_actualizacion_usu = None

        usuario = Usuario(
            correo_usu=correo,
            cedula_usu=cedula,
            telefono_usu=telefono,
            nombres_usu=nombres,
            primer_apellido_usu=p_apellido,
            segundo_apellido_usu=s_apellido,
            direccion_usu=direccion,
            rol_usu='entrenador',
            estado_invitacion='pendiente',
            estado_usu='activo',
            is_active=True,
            is_staff=False,  # si no debe tener acceso admin
            fecha_creacion_usu=timezone.now(),
            fecha_actualizacion_usu=None,
        )
        usuario.set_unusable_password()
        usuario.save()
        # ⚠️ AQUÍ FALTABA ESTO: crear el objeto Entrenador
        entrenador = Entrenador(
            fk_id_usu=usuario,
            fecha_creacion_ent=timezone.now(),
            fecha_actualizacion_ent=None
        )
        entrenador.save()

        token = get_random_string(64)
        TokenPassword.objects.create(
            fk_id_usu=usuario,
            token=token,
            usado_tok=False
        )

        enlace = request.build_absolute_uri(reverse('activar_contrasena', args=[token]))

        cuerpo = f"""
        <div style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 30px;">
            <div style="max-width: 600px; margin: auto; background: #fff; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); padding: 40px;">
                <h2 style="color: #333;">¡Hola, {nombres}!</h2>
                <p style="font-size: 16px; color: #555;">
                    Has sido registrado como <strong>Entrenador</strong> en el Sistema de Entrenamientos.
                </p>
                <p style="font-size: 16px; color: #555;">
                    Para activar tu cuenta y establecer una contraseña, haz clic en el siguiente botón:
                </p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{enlace}" style="
                        background-color: #28a745;
                        color: #fff;
                        text-decoration: none;
                        padding: 12px 24px;
                        font-size: 16px;
                        border-radius: 5px;
                        display: inline-block;
                        font-weight: bold;">
                        Activar Cuenta
                    </a>
                </div>
                <p style="font-size: 14px; color: #999;">
                    Si no solicitaste este acceso, puedes ignorar este correo.
                </p>
                <hr style="margin-top: 40px; border: none; border-top: 1px solid #eee;">
                <p style="text-align: center; color: #ccc; font-size: 12px;">
                    © 2025 Sistema de Entrenamientos
                </p>
            </div>
        </div>
        """

        email = EmailMessage(
            subject="Crea tu contraseña de Entrenador",
            body=cuerpo,
            to=[correo],
        )
        email.content_subtype = "html"
        email.send(fail_silently=True)

        messages.success(request, f"Invitación enviada a {correo}.")

    return redirect('list_entrenadores')

@login_required
def edit_entrenador(request, pk):
    if request.user.rol_usu not in ['admin_dios', 'admin']:
        messages.error(request, "No tienes permiso para editar entrenadores.")
        return redirect('admin_dashboard')

    entrenador = get_object_or_404(Usuario, pk=pk, rol_usu='entrenador')

    if request.method == 'POST':
        entrenador.correo_usu = request.POST['correo_usu']
        entrenador.cedula_usu = request.POST['cedula_usu']
        entrenador.telefono_usu = request.POST['telefono_usu']
        entrenador.nombres_usu = request.POST['nombres_usu']
        entrenador.primer_apellido_usu = request.POST['primer_apellido_usu']
        entrenador.segundo_apellido_usu = request.POST['segundo_apellido_usu']
        entrenador.direccion_usu = request.POST['direccion_usu']
        entrenador.estado_usu = request.POST['estado_usu'].lower()
        entrenador.fecha_actualizacion_usu = timezone.now()
        entrenador.save()

        messages.success(request, "Entrenador actualizado correctamente.")

    return redirect('list_entrenadores')  # Cambia esta URL si tu url es distinta


@login_required
def delete_entrenador(request, pk):
    if request.user.rol_usu not in ['admin_dios', 'admin']:
        messages.error(request, "No tienes permiso para esta acción.")
        return redirect('list_entrenadores')

    if request.method == 'POST':
        password = request.POST.get('confirm_password')

        if not request.user.check_password(password):
            messages.error(request, "Contraseña incorrecta. No se pudo eliminar.")
            return redirect('list_entrenadores')

        try:
            entrenador = get_object_or_404(Usuario, pk=pk, rol_usu='entrenador')
            TokenPassword.objects.filter(fk_id_usu=entrenador).delete()
            entrenador.delete()
            messages.success(request, "Entrenador eliminado correctamente.")
        except ProtectedError:
            messages.error(request, "No se puede eliminar este entrenador porque tiene registros protegidos.")
        except Exception as e:
            messages.error(request, f"Ocurrió un error inesperado: {e}")

    return redirect('list_entrenadores')  # Cambia esta URL si tu url es distinta

# -------------------------------CRUD CATEGORIAS-----------------------------


# Listar Categorías
@login_required
def list_categoria(request):
    if request.user.rol_usu not in ['admin_dios', 'admin']:
        messages.warning(request, "No tienes permiso para acceder aquí.")
        return redirect('admin_dashboard')

    categorias = Categoria.objects.all()  # Obtienes todas las categorías de la base de datos

    return render(request, 'Categoria/listCategoria.html', {'categorias': categorias})

# Crear Categoría
@login_required
def add_categoria(request):
    if request.user.rol_usu not in ['admin_dios', 'admin']:
        messages.error(request, "No tienes permiso para crear categorías.")
        return redirect('admin_dashboard')

    if request.method == 'POST':
        nombre_cat = request.POST['nombre_cat']
        descripcion_cat = request.POST['descripcion_cat']
        fecha_creacion_cat = timezone.now()
        fecha_actualizacion_cat = None

         # Si la descripción está vacía, asignamos "Sin descripción" por defecto
        if not descripcion_cat:
            descripcion_cat = "SIN DESCRIPCIÓN"



        # Crear y guardar la nueva categoría
        categoria = Categoria(
            nombre_cat=nombre_cat,
            descripcion_cat=descripcion_cat,
            fecha_creacion_cat=fecha_creacion_cat,
            fecha_actualizacion_cat=fecha_actualizacion_cat,
        )
        categoria.save()

        # Mensaje de éxito
        messages.success(request, f"Categoría '{nombre_cat}' creada exitosamente.")

        # No redirigir a otra vista, solo cerrar el modal y refrescar la lista
        return redirect('list_categoria')  # Esta línea es opcional, depende de si deseas refrescar la lista después de agregar

    return redirect('list_categoria')  

# Editar categoría
@login_required
def edit_categoria(request, pk):
    if request.user.rol_usu not in ['admin_dios', 'admin']:
        messages.error(request, "No tienes permiso para editar categorías.")
        return redirect('list_categoria')

    categoria = get_object_or_404(Categoria, pk=pk)

    if request.method == 'POST':
        categoria.nombre_cat = request.POST['nombre_cat']
        categoria.descripcion_cat = request.POST['descripcion_cat']
        categoria.estado_cat = request.POST['estado_cat'].lower()  # Asegúrate que sea minúsculo
        categoria.fecha_actualizacion_cat = timezone.now()
        categoria.save()

        messages.success(request, "Categoría actualizada correctamente.")

    return redirect('list_categoria')



# Eliminar categoría
@login_required
def delete_categoria(request, pk):
    if request.user.rol_usu not in ['admin_dios', 'admin']:
        messages.error(request, "No tienes permiso para esta acción.")
        return redirect('list_categoria')

    if request.method == 'POST':
        try:
            # Intentamos obtener la categoría a eliminar
            categoria = get_object_or_404(Categoria, pk=pk)

            # Verificamos si existen equipos asociados a esta categoría
            if categoria.equipo_set.exists():  # Esto verifica si hay equipos vinculados
                messages.error(request, "No se puede eliminar esta categoría porque tiene equipos asociados.")
                return redirect('list_categoria')

            # Si no hay equipos asociados, procedemos a eliminar la categoría
            categoria.delete()
            messages.success(request, "Categoría eliminada correctamente.")
        except Exception as e:
            messages.error(request, f"Ocurrió un error inesperado: {e}")

    return redirect('list_categoria')

# -------------------------------CRUD TEMPORADAS ----------------------------


# Listar Temporadas
@login_required
def list_temporadas(request):
    if request.user.rol_usu not in ['admin_dios', 'admin']:
        messages.warning(request, "No tienes permiso para acceder aquí.")
        return redirect('admin_dashboard')

    temporadas = Temporada.objects.all()
    return render(request, 'Temporada/listTemporada.html', {'temporadas': temporadas})

# Crear Temporada
@login_required
def add_temporada(request):
    if request.user.rol_usu not in ['admin_dios', 'admin']:
        messages.error(request, "No tienes permiso para crear temporadas.")
        return redirect('admin_dashboard')

    if request.method == 'POST':
        fecha_inicio = request.POST.get('fecha_inicio_temp')
        fecha_fin = request.POST.get('fecha_fin_temp')
        fecha_creacion_temp = timezone.now()
        fecha_actualizacion_temp = None

        temporada = Temporada(
            fecha_inicio_temp=fecha_inicio,
            fecha_fin_temp=fecha_fin,
            fecha_creacion_temp=fecha_creacion_temp,
            fecha_actualizacion_temp=fecha_actualizacion_temp
        )
        temporada.save()
        messages.success(request, "Temporada creada exitosamente.")
        return redirect('list_temporadas')

    return redirect('list_temporadas')

# Editar Temporada
@login_required
def edit_temporada(request, pk):
    if request.user.rol_usu not in ['admin_dios', 'admin']:
        messages.error(request, "No tienes permiso para editar temporadas.")
        return redirect('list_temporadas')

    temporada = get_object_or_404(Temporada, pk=pk)

    if request.method == 'POST':
        temporada.fecha_inicio_temp = request.POST['fecha_inicio_temp']
        temporada.fecha_fin_temp = request.POST['fecha_fin_temp']
        temporada.fecha_actualizacion_temp = timezone.now()
        temporada.save()
        messages.success(request, "Temporada actualizada correctamente.")

    return redirect('list_temporadas')

# Eliminar Temporada
@login_required
def delete_temporada(request, pk):
    if request.user.rol_usu not in ['admin_dios', 'admin']:
        messages.error(request, "No tienes permiso para esta acción.")
        return redirect('list_temporadas')

    if request.method == 'POST':
        try:
            temporada = get_object_or_404(Temporada, pk=pk)
            temporada.delete()
            messages.success(request, "Temporada eliminada correctamente.")
        except Exception as e:
            messages.error(request, f"Ocurrió un error: {e}")

    return redirect('list_temporadas')



# -------------------------------CRUD EQUIPOS ----------------------------


@login_required
def list_equipo(request):
    if request.user.rol_usu not in ['admin_dios', 'admin']:
        messages.warning(request, "No tienes permiso para acceder aquí.")
        return redirect('admin_dashboard')

    equipos = Equipo.objects.prefetch_related('categorias').all()
    
    # Agregar IDs de categorías directamente a cada equipo
    for equipo in equipos:
        equipo.categorias_ids = list(equipo.categorias.values_list('id', flat=True))
    
    categorias = Categoria.objects.all()

    context = {
        'equipos': equipos,
        'categorias': categorias,
    }
    return render(request, 'Equipo/listEquipo.html', context)


# AGREGAR EQUIPO
@login_required
def add_equipo(request):
    if request.user.rol_usu not in ['admin_dios', 'admin']:
        messages.error(request, "No tienes permiso para agregar equipos.")
        return redirect('list_equipo')

    if request.method == 'POST':
        nombre = request.POST.get('nombre_equ')
        descripcion = request.POST.get('descripcion_equ') or "SIN DESCRIPCIÓN"
        logo = request.FILES.get('logo_equ')
        fecha_fundado = request.POST.get('fecha_fundado_equ')
        if fecha_fundado == '':
            fecha_fundado = None

        categorias_ids = request.POST.getlist('categorias')
        fecha_creacion_equ=timezone.now(),  # explícito aunque es auto_now_add
        fecha_actualizacion_equ=None  # No ha sido editado aún

        equipo = Equipo(nombre_equ=nombre, descripcion_equ=descripcion, fecha_fundado_equ=fecha_fundado, logo_equ=logo, fecha_creacion_equ=fecha_creacion_equ, fecha_actualizacion_equ=fecha_actualizacion_equ)
        equipo.save()

        if categorias_ids:
            equipo.categorias.set(categorias_ids)

        messages.success(request, "Equipo creado exitosamente.")
        return redirect('list_equipo')

    return redirect('list_equipo')

@login_required
def edit_equipo(request, pk):
    if request.user.rol_usu not in ['admin_dios', 'admin']:
        messages.error(request, "No tienes permiso para editar equipos.")
        return redirect('list_equipo')

    equipo = get_object_or_404(Equipo, pk=pk)

    if request.method == 'POST':
        equipo.nombre_equ = request.POST.get('nombre_equ')
        equipo.descripcion_equ = request.POST.get('descripcion_equ') or "SIN DESCRIPCIÓN"
        equipo.fecha_fundado_equ = request.POST.get('fecha_fundado_equ')
        equipo.fecha_actualizacion_equ = timezone.now()

        if equipo.fecha_fundado_equ == '':
            equipo.fecha_fundado_equ = None

        eliminar_logo = request.POST.get('eliminar_logo', 'false')
        nuevo_logo = request.FILES.get('logo_equ_edi')

        if eliminar_logo == 'true':
            if equipo.logo_equ:
                equipo.logo_equ.delete(save=False)  # Borra el archivo físico
            equipo.logo_equ = None

        if nuevo_logo:
            if equipo.logo_equ:
                equipo.logo_equ.delete(save=False)
            equipo.logo_equ = nuevo_logo

        categorias_ids = request.POST.getlist('categorias')
        equipo.categorias.set(categorias_ids)

        equipo.save()
        messages.success(request, "Equipo actualizado correctamente.")
        return redirect('list_equipo')

    return redirect('list_equipo')


# ELIMINAR EQUIPO
@login_required
def delete_equipo(request, pk):
    if request.user.rol_usu not in ['admin_dios', 'admin']:
        messages.error(request, "No tienes permiso para eliminar equipos.")
        return redirect('list_equipo')

    if request.method == 'POST':
        equipo = get_object_or_404(Equipo, pk=pk)

        # Validación de relaciones (por ejemplo, jugadores)
        if equipo.jugador_set.exists():
            messages.error(request, "No se puede eliminar el equipo porque tiene jugadores asociados.")
            return redirect('list_equipo')

        equipo.delete()
        messages.success(request, "Equipo eliminado correctamente.")
        return redirect('list_equipo')

    return redirect('list_equipo')





# -------------------------------CRUD JUGADORES ----------------------------
@login_required
def list_jugadores(request):
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.warning(request, "No tienes permiso para acceder aquí.")
        return redirect('admin_dashboard')

    jugadores = Jugador.objects.select_related('fk_id_usu', 'fk_id_equ', 'fk_id_cat', 'fk_id_ent__fk_id_usu').all()
    equipos = Equipo.objects.prefetch_related('categorias').all()
    categorias = Categoria.objects.all()
    entrenadores = Entrenador.objects.select_related('fk_id_usu').all()

    context = {
        'jugadores': jugadores,
        'equipos': equipos,
        'categorias': categorias,
        'entrenadores': entrenadores
    }

    return render(request, 'Jugadores/listJugadores.html', context)




@login_required
def add_jugador(request):
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.error(request, "No tienes permiso para crear jugadores.")
        return redirect('admin_dashboard')
        
    equipos = Equipo.objects.prefetch_related('categorias').all()
    categorias = Categoria.objects.all()
    entrenador = Entrenador.objects.filter(fk_id_usu=request.user).first()
    if not entrenador:
        messages.error(request, "Este usuario no está registrado como entrenador.")
        return redirect('list_jugadores')

    fk_id_ent_id = entrenador.id


    if request.method == 'POST':
        correo     = request.POST['correo_usu']
        cedula     = request.POST['cedula_usu']
        telefono   = request.POST.get('telefono_usu', '')
        nombres    = request.POST['nombres_usu']
        p_apellido = request.POST['primer_apellido_usu']
        s_apellido = request.POST['segundo_apellido_usu']
        direccion  = request.POST.get('direccion_usu', '')

        # Datos específicos del jugador
        fecha_nacimiento = request.POST.get('fecha_nacimiento_jug', None)
        edad             = request.POST.get('edad_jug', None)
        numero           = request.POST.get('numero_jug', None)
        peso             = request.POST.get('peso_jug', None)
        altura           = request.POST.get('altura_jug', None)
        posicion         = request.POST.get('posicion_jug', '')
        pie_dominante    = request.POST.get('pie_dominante_jug', '')
        nombre_rep       = request.POST.get('nombre_representante_jug', '')
        numero_emer      = request.POST.get('numero_emergencia_jug', '')
        fecha_ingreso    = request.POST.get('fecha_ingreso_jug', None)

        fk_id_equ_id     = request.POST.get('fk_id_equ', None)
        fk_id_cat_id     = request.POST.get('fk_id_cat', None)

        # Si es entrenador, se asigna a sí mismo. Si es admin, se selecciona desde el formulario
        if request.user.rol_usu == 'entrenador':
            fk_id_ent_id = fk_id_ent_id
        else:
            fk_id_ent_id = request.POST.get('fk_id_ent', None)

        # Crear usuario jugador
        usuario = Usuario(
            correo_usu=correo,
            cedula_usu=cedula,
            telefono_usu=telefono,
            nombres_usu=nombres,
            primer_apellido_usu=p_apellido,
            segundo_apellido_usu=s_apellido,
            direccion_usu=direccion,
            rol_usu='jugador',
            estado_invitacion='pendiente',
            estado_usu='activo',
            is_active=True,
            is_staff=False,
            fecha_creacion_usu=timezone.now(),
            fecha_actualizacion_usu=None
        )
        usuario.set_unusable_password()
        usuario.save()

        # Crear jugador
        jugador = Jugador(
            fk_id_usu=usuario,
            fecha_nacimiento_jug=fecha_nacimiento or None,
            edad_jug=int(edad) if edad else None,
            numero_jug=int(numero) if numero else None,
            peso_jug=peso if peso else None,
            altura_jug=altura if altura else None,
            posicion_jug=posicion,
            pie_dominante_jug=pie_dominante,
            nombre_representante_jug=nombre_rep,
            numero_emergencia_jug=numero_emer,
            fecha_ingreso_jug=fecha_ingreso or None,
            fk_id_equ_id=fk_id_equ_id or None,
            fk_id_cat_id=fk_id_cat_id or None,
            fk_id_ent_id=fk_id_ent_id or None,
            fecha_creacion_jug=timezone.now(),
            fecha_actualizacion_jug=None
        )
        jugador.save()

        # Generar token y enviar email de activación
        token = get_random_string(64)
        TokenPassword.objects.create(
            fk_id_usu=usuario,
            token=token,
            usado_tok=False
        )

        enlace = request.build_absolute_uri(reverse('activar_contrasena', args=[token]))

        cuerpo = f"""
        <div style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 30px;">
            <div style="max-width: 600px; margin: auto; background: #fff; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); padding: 40px;">
                <h2 style="color: #333;">¡Hola, {nombres}!</h2>
                <p style="font-size: 16px; color: #555;">
                    Has sido registrado como <strong>Jugador</strong> en el Sistema de Entrenamientos.
                </p>
                <p style="font-size: 16px; color: #555;">
                    Para activar tu cuenta y establecer una contraseña, haz clic en el siguiente botón:
                </p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{enlace}" style="
                        background-color: #28a745;
                        color: #fff;
                        text-decoration: none;
                        padding: 12px 24px;
                        font-size: 16px;
                        border-radius: 5px;
                        display: inline-block;
                        font-weight: bold;">
                        Activar Cuenta
                    </a>
                </div>
                <p style="font-size: 14px; color: #999;">
                    Si no solicitaste este acceso, puedes ignorar este correo.
                </p>
                <hr style="margin-top: 40px; border: none; border-top: 1px solid #eee;">
                <p style="text-align: center; color: #ccc; font-size: 12px;">
                    © 2025 Sistema de Entrenamientos
                </p>
            </div>
        </div>
        """

        email = EmailMessage(
            subject="Crea tu contraseña de Jugador",
            body=cuerpo,
            to=[correo],
        )
        email.content_subtype = "html"
        email.send(fail_silently=True)

        messages.success(request, f"Invitación enviada a {correo}.")

        return redirect('list_jugadores')  # 👈 Redirige solo si todo salió bien

    # Si es GET u otra cosa, renderiza el formulario
    return redirect('list_jugadores')  # en caso de acceso incorrecto




@login_required
def edit_jugador(request):
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.error(request, "No tienes permiso para editar jugadores.")
        return redirect('admin_dashboard')

    if request.method == 'POST':
        jugador = get_object_or_404(Jugador, pk=request.POST['id_jug'])
        usuario_id = request.POST.get('id_usu') or jugador.fk_id_usu_id
        if not usuario_id:
            messages.error(request, "El jugador no tiene usuario asociado.")
            return redirect('list_jugadores')
        usuario = get_object_or_404(Usuario, pk=usuario_id)

        # Actualizar Usuario
        nuevo_correo = request.POST['correo_usu']
        nueva_cedula = request.POST['cedula_usu']

        # Solo verificar duplicados si se modificó el dato. Esto evita errores
        # cuando el usuario intenta guardar sin cambiar su correo o cédula.
        if nuevo_correo != usuario.correo_usu:
            if Usuario.objects.exclude(pk=usuario.pk).filter(correo_usu=nuevo_correo).exists():
                messages.error(request, "Este correo ya está registrado.")
                return redirect('list_jugadores')

        if nueva_cedula != usuario.cedula_usu:
            if Usuario.objects.exclude(pk=usuario.pk).filter(cedula_usu=nueva_cedula).exists():
                messages.error(request, "Esta cédula ya está registrada.")
                return redirect('list_jugadores')

        usuario.correo_usu = nuevo_correo
        usuario.cedula_usu = nueva_cedula
        usuario.telefono_usu = request.POST['telefono_usu']
        usuario.nombres_usu = request.POST['nombres_usu']
        usuario.primer_apellido_usu = request.POST['primer_apellido_usu']
        usuario.segundo_apellido_usu = request.POST['segundo_apellido_usu']
        usuario.direccion_usu = request.POST['direccion_usu']
        usuario.estado_usu = request.POST['estado_usu']
        usuario.fecha_actualizacion_usu = timezone.now()
        usuario.save()

        # Actualizar Jugador
        jugador.fecha_nacimiento_jug = request.POST['fecha_nacimiento_jug']
        jugador.edad_jug = request.POST['edad_jug']
        jugador.numero_jug = request.POST['numero_jug']
        jugador.peso_jug = request.POST['peso_jug']
        jugador.altura_jug = request.POST['altura_jug']
        jugador.posicion_jug = request.POST['posicion_jug'].upper()
        jugador.pie_dominante_jug = request.POST['pie_dominante_jug'].upper()
        jugador.nombre_representante_jug = request.POST['nombre_representante_jug']
        jugador.numero_emergencia_jug = request.POST['numero_emergencia_jug']
        jugador.fecha_ingreso_jug = request.POST['fecha_ingreso_jug']
        jugador.fk_id_equ_id = request.POST.get('fk_id_equ') or None
        jugador.fk_id_cat_id = request.POST.get('fk_id_cat') or None
        jugador.fk_id_ent_id = request.POST.get('fk_id_ent') or None
        jugador.fecha_actualizacion_jug = timezone.now()
        jugador.save()

        messages.success(request, "Jugador actualizado correctamente.")
        return redirect('list_jugadores')


@login_required
def delete_jugador(request, pk):
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.error(request, "No tienes permiso para eliminar jugadores.")
        return redirect('list_jugadores')

    if request.method == 'POST':
        jugador = get_object_or_404(Jugador, pk=pk)

        if jugador.prueba_set.exists() or jugador.resultadomacro_set.exists():
            messages.error(request, "No se puede eliminar el jugador porque tiene registros asociados.")
            return redirect('list_jugadores')

        usuario = jugador.fk_id_usu
        try:
            jugador.delete()
            if usuario:
                TokenPassword.objects.filter(fk_id_usu=usuario).delete()
                usuario.delete()
            messages.success(request, "Jugador eliminado correctamente.")
        except ProtectedError:
            messages.error(request, "No se puede eliminar el jugador porque tiene registros protegidos.")
        return redirect('list_jugadores')

    
# -------------------------------CRUD TIPO EVALUACION-------------------------------
#listar
@login_required
def list_tipoevaluaciones(request):
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.warning(request, "No tienes permiso para acceder aquí.")
        return redirect('admin_dashboard')

    # Obtener todos los tipos de evaluación
    tipos_evaluacion = TipoEvaluacion.objects.all()

    # Obtener todos los parámetros asociados a cada tipo de evaluación
    # Se obtiene usando el campo fk_tipo_evaluacion de ParametroEvaluacion
    parametros_evaluacion = ParametroEvaluacion.objects.all()

    return render(request, 'TipoEvaluacion/listTipoEvaluaciones.html', {
        'tipos_evaluacion': tipos_evaluacion,
        'parametros_evaluacion': parametros_evaluacion
    })

@login_required
def add_tipoevaluacion(request):
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.error(request, "No tienes permiso para crear tipos de evaluación.")
        return redirect('admin_dashboard')

    if request.method == 'POST':
        nombre_tip = request.POST['nombre_tip']
        descripcion_tip = request.POST.get('descripcion_tip', '').strip()
        fecha_creacion_tip = timezone.now()

        # Si la descripción está vacía, asignar el valor por defecto
        if not descripcion_tip:
            descripcion_tip = "SIN DESCRIPCIÓN"

        tipo_evaluacion = TipoEvaluacion(
            nombre_tip=nombre_tip,
            descripcion_tip=descripcion_tip,
            fecha_creacion_tip=fecha_creacion_tip
        )
        tipo_evaluacion.save()

        # Ahora agregamos los parámetros para este tipo de evaluación
        titulos = request.POST.getlist('titulo_det[]')
        descripcion = request.POST.getlist('descripcion_det[]')

        # Recorremos los parámetros y guardamos o actualizamos
        for titulo, desc in zip(titulos, descripcion):
            if titulo.strip() and desc.strip():
                # Si el campo de descripción está vacío, asignamos el valor por defecto
                if not desc.strip():
                    desc = "SIN DESCRIPCIÓN"

                ParametroEvaluacion.objects.create(
                    nombre_prm=titulo.strip(),
                    descripcion_prm=desc.strip(),
                    fk_tipo_evaluacion=tipo_evaluacion,
                    fecha_creacion_prm=timezone.now()
                )

        messages.success(request, f"Tipo de Evaluación '{nombre_tip}' y sus parámetros fueron creados exitosamente.")
        return redirect('list_tipoevaluaciones')

    return redirect('list_tipoevaluaciones')
@login_required
def edit_tipoevaluacion(request, pk):
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.error(request, "No tienes permiso para editar tipos de evaluación.")
        return redirect('list_tipoevaluaciones')

    tipo_evaluacion = get_object_or_404(TipoEvaluacion, pk=pk)

    if request.method == 'POST':
        try:
            # Actualizar tipo de evaluación
            tipo_evaluacion.nombre_tip = request.POST['nombre_tip']
            
            # Si no se ingresa una descripción, poner "SIN DESCRIPCIÓN"
            tipo_evaluacion.descripcion_tip = request.POST.get('descripcion_tip', '').strip() or "SIN DESCRIPCIÓN"
            
            tipo_evaluacion.fecha_actualizacion_tip = timezone.now()
            tipo_evaluacion.save()

            # Obtener parámetros del formulario
            titulos = request.POST.getlist('titulo_det[]')
            descripciones = request.POST.getlist('descripcion_det[]')
            ids_parametros = request.POST.getlist('detalle_id[]')
            
            # Procesar parámetros existentes
            parametros_existentes = ParametroEvaluacion.objects.filter(fk_tipo_evaluacion=tipo_evaluacion)
            ids_existentes = [str(p.id) for p in parametros_existentes]
            
            # Identificar parámetros a eliminar
            ids_eliminar = set(ids_existentes) - set(ids_parametros)
            if ids_eliminar:
                ParametroEvaluacion.objects.filter(id__in=ids_eliminar).delete()
            
            # Actualizar/crear parámetros
            for i in range(len(titulos)):
                titulo = titulos[i].strip()
                descripcion = descripciones[i].strip() or "SIN DESCRIPCIÓN"  # Si la descripción está vacía, poner "SIN DESCRIPCIÓN"
                param_id = ids_parametros[i]
                
                if not titulo:
                    continue  # Si no se ha ingresado un título, no procesamos ese parámetro
                
                if param_id and param_id != '':  # Actualizar existente
                    parametro = ParametroEvaluacion.objects.filter(
                        id=param_id, 
                        fk_tipo_evaluacion=tipo_evaluacion
                    ).first()
                    if parametro:
                        parametro.nombre_prm = titulo
                        parametro.descripcion_prm = descripcion
                        parametro.fecha_actualizacion_prm = timezone.now()
                        parametro.save()
                else:  # Crear nuevo
                    ParametroEvaluacion.objects.create(
                        fk_tipo_evaluacion=tipo_evaluacion,
                        nombre_prm=titulo,
                        descripcion_prm=descripcion,
                        fecha_creacion_prm=timezone.now()
                    )

            messages.success(request, "Tipo de Evaluación actualizado correctamente.")
        except Exception as e:
            messages.error(request, f"Error al actualizar: {str(e)}")

    return redirect('list_tipoevaluaciones')



# Eliminar tipo de evaluación
@login_required
def delete_tipoevaluacion(request, pk):
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.error(request, "No tienes permiso para esta acción.")
        return redirect('list_tipoevaluaciones')

    if request.method == 'POST':
        try:
            tipo = get_object_or_404(TipoEvaluacion, pk=pk)
            tipo.delete()
            messages.success(request, "Tipo de Evaluación eliminado correctamente.")
        except Exception as e:
            messages.error(request, f"Ocurrió un error inesperado: {e}")

    return redirect('list_tipoevaluaciones')



# -------------------------------CRUD PRUEBAS-------------------------------
@login_required
def list_pruebas(request):
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.warning(request, "No tienes permiso para acceder aquí.")
        return redirect('admin_dashboard')

    pruebas = Prueba.objects.select_related('fk_id_jug__fk_id_usu', 'fk_id_tip').all()
    jugadores = Jugador.objects.select_related('fk_id_usu').all()
    evaluaciones = TipoEvaluacion.objects.all()  # Cargar tipos de evaluación (no Evaluacion)
    hoy = timezone.now().date()

    return render(request, 'Prueba/listPrueba.html', {
        'pruebas': pruebas,
        'jugadores': jugadores,
        'evaluaciones': evaluaciones,  # Ahora estamos pasando los tipos de evaluación
        'hoy': hoy
    })


@login_required
def add_prueba(request):
    if request.user.rol_usu not in ['admin_dios', 'entrenador']:
        messages.error(request, "No tienes permiso para crear pruebas.")
        return redirect('admin_dashboard')

    if request.method == 'POST':
        try:
            entrenador = Entrenador.objects.get(fk_id_usu=request.user)

            # Crear la prueba
            prueba = Prueba.objects.create(
                fk_id_ent=entrenador,
                fk_id_jug_id=request.POST['fk_id_jug'],
                fk_id_tip_id=request.POST['fk_id_eva'],
                macro_pru=request.POST.get('macro_pru', '').strip(),
                observaciones_pru=request.POST.get('observaciones_pru', '').strip() or "SIN OBSERVACIONES",
                fecha_pru=request.POST.get('fecha_pru'),
                fecha_creacion_pru=timezone.now()
            )

            # Capturar los detalles de los parámetros
            parametro_ids = request.POST.getlist('parametro_id[]')  # Lista de IDs de parámetros seleccionados
            valoraciones = request.POST.getlist('valoracion_det[]')  # Lista de valoraciones

            for parametro_id, valoracion in zip(parametro_ids, valoraciones):
                if parametro_id and valoracion.strip():
                    parametro = ParametroEvaluacion.objects.get(id=parametro_id)
                    DetallePrueba.objects.create(
                        fk_id_pru=prueba,
                        fk_id_parametro=parametro,
                        valoracion_det=valoracion.strip(),
                        fecha_creacion_det=timezone.now()
                    )

            messages.success(request, "Prueba y detalles registrados exitosamente.")
        except Exception as e:
            messages.error(request, f"Ocurrió un error al registrar la prueba: {e}")

    return redirect('list_pruebas')


@login_required
def get_parametros(request, evaluacion_id):
    parametros = ParametroEvaluacion.objects.filter(fk_tipo_evaluacion_id=evaluacion_id)
    parametros_data = [
        {"id": parametro.id, "titulo": parametro.nombre_prm}
        for parametro in parametros
    ]
    return JsonResponse(parametros_data, safe=False)






@login_required
def edit_prueba(request, pk):
    if request.user.rol_usu not in ['admin_dios', 'entrenador']:
        messages.error(request, "No tienes permiso para editar pruebas.")
        return redirect('list_pruebas')

    prueba = get_object_or_404(Prueba, pk=pk)

    if request.method == 'POST':
        try:
            prueba.fk_id_jug = Jugador.objects.get(pk=request.POST['fk_id_jug'])

            prueba.fk_id_tip = TipoEvaluacion.objects.get(pk=request.POST['fk_id_tip'])

            prueba.macro_pru = request.POST.get('macro_pru', '')
            prueba.observaciones_pru = request.POST.get('observaciones_pru', '').strip() or "SIN OBSERVACIONES"
            prueba.fecha_pru = request.POST.get('fecha_pru')
            prueba.fecha_actualizacion_pru = timezone.now()
            prueba.save()

            # Eliminar detalles antiguos
            DetallePrueba.objects.filter(fk_id_pru=prueba).delete()

            # Insertar nuevos detalles
            parametro_ids = request.POST.getlist('parametro_id[]')
            valoraciones = request.POST.getlist('valoracion_det[]')

            for parametro_id, valor in zip(parametro_ids, valoraciones):
                if parametro_id and valor.strip():
                    DetallePrueba.objects.create(
                        fk_id_pru=prueba,
                        fk_id_parametro_id=parametro_id,
                        valoracion_det=valor.strip(),
                        fecha_creacion_det=timezone.now()
                    )

            messages.success(request, "Prueba actualizada correctamente.")
        except Exception as e:
            messages.error(request, f"Ocurrió un error al actualizar la prueba: {e}")

    return redirect('list_pruebas')



@login_required
def delete_prueba(request, pk):
    if request.user.rol_usu not in ['admin_dios', 'admin']:
        messages.error(request, "No tienes permiso para esta acción.")
        return redirect('list_pruebas')

    if request.method == 'POST':
        try:
            prueba = get_object_or_404(Prueba, pk=pk)
            prueba.delete()
            messages.success(request, "Prueba eliminada correctamente.")
        except Exception as e:
            messages.error(request, f"Ocurrió un error inesperado: {e}")

    return redirect('list_pruebas')
