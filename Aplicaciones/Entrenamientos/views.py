from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.views.generic import View
from django.contrib.auth.decorators import login_required
from django.utils.crypto import get_random_string
from django.core.mail import EmailMessage
from django.urls import reverse
from django.db.models import ProtectedError
from django.contrib import messages
from .models import *
from django.utils import timezone
import calendar
from django.db.models import Q
import pytz
import uuid
from django.views.decorators.http import require_GET
from django.http import JsonResponse
from django.http import HttpResponse
from collections import defaultdict
from django.db.models import Avg

def index(request):
    return render(request, 'index.html')

from django.contrib.auth import authenticate, login
from django.shortcuts import redirect
from django.contrib import messages
from django.views import View

class CustomLoginView(View):
    def get(self, request):
        return render(request, 'registration/login.html')

    def post(self, request):
        correo = request.POST.get('correo_usu')
        password = request.POST.get('password')

        user = authenticate(request, correo_usu=correo, password=password)

        if user is not None:
            if hasattr(user, 'estado_usu') and user.estado_usu == 'activo':
                login(request, user)
                # Aquí rediriges según el rol del usuario
                if user.rol_usu == 'admin_dios':
                    return redirect('admin_dashboard')  # Dashboard para admin_dios
                elif user.rol_usu == 'admin':
                    return redirect('admin_dashboard')  # Dashboard para admin
                elif user.rol_usu == 'entrenador':
                    return redirect('dashboard_entrenador')  # Dashboard para entrenador
                elif user.rol_usu == 'jugador':
                    return redirect('dashboard_jugador')  # Dashboard para jugador
                else:
                    return redirect('login')  # Si no tiene rol definido, lo rediriges al login
            else:
                messages.error(request, "Tu cuenta está inactiva. Contacta al administrador.")
                return redirect('login')
        else:
            messages.error(request, "Correo o contraseña incorrectos.")
            return redirect('login')


def CustomLogoutView(request):
    logout(request)
    return redirect('index')

#VALIDACION EN BDD
@require_GET
def validate_correo(request):
    correo = request.GET.get('correo_usu')
    exclude_id = request.GET.get('exclude_id')

    print(f"correo: {correo}, exclude_id: {exclude_id}")  # Depuración para verificar los valores

    qs = Usuario.objects.filter(correo_usu=correo)
    if exclude_id:
        try:
            qs = qs.exclude(pk=int(exclude_id))
        except (TypeError, ValueError):
            pass

    existe = qs.exists()
    return HttpResponse("false" if existe else "true", content_type="application/json")

@require_GET
def validate_cedula(request):
    cedula = request.GET.get('cedula_usu')
    exclude_id = request.GET.get('exclude_id')

    print(f"cedula: {cedula}, exclude_id: {exclude_id}")  # Depuración para verificar los valores

    qs = Usuario.objects.filter(cedula_usu=cedula)
    if exclude_id:
        try:
            qs = qs.exclude(pk=int(exclude_id))
        except (TypeError, ValueError):
            pass

    existe = qs.exists()
    return HttpResponse("false" if existe else "true", content_type="application/json")



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

    admins = Usuario.objects.filter(rol_usu='admin').order_by('id_usu')
    return render(request, 'Admin/listAdmin.html', {
        'admins': admins,
        'rol_usuario': request.user.rol_usu,
        'usuario': request.user
    })

#AGREGAR ADMINISTRADOR

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
            fecha_creacion_usu=fecha_creacion_usu,
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
    else:
        return render(request, 'Admin/addAdmin.html', {
            'rol_usuario': request.user.rol_usu,
            'usuario': request.user
        })





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
        return redirect('list_admins')  # SOLO AQUÍ REDIRIGE

    # Si GET, aquí se renderiza el formulario con los datos actuales:
    return render(request, 'Admin/editAdmin.html', {'admin': admin, 'rol_usuario': request.user.rol_usu, 'usuario': request.user})


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

    context = {
        'entrenadores': entrenadores,
        'rol_usuario': request.user.rol_usu,
        'usuario': request.user
    }
    return render(request, 'Entrenador/listEntrenador.html', context)





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

        # Comprobar si ya existe un usuario con ese correo o cédula
        if Usuario.objects.filter(correo_usu=correo).exists():
            messages.error(request, "Ya existe un usuario con ese correo.")
            return redirect('add_entrenador')
        if Usuario.objects.filter(cedula_usu=cedula).exists():
            messages.error(request, "Ya existe un usuario con esa cédula.")
            return redirect('add_entrenador')

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
            is_staff=False,
            fecha_creacion_usu=timezone.now(),
            fecha_actualizacion_usu=None,
        )
        usuario.set_unusable_password()
        usuario.save()

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
        return redirect('list_entrenadores')  # Redirige al listado después de agregar

    # GET
    context = {
        'rol_usuario': request.user.rol_usu,
        'usuario': request.user
    }
    return render(request, 'Entrenador/addEntrenador.html', context)




@login_required
def edit_entrenador(request, pk):
    if request.user.rol_usu not in ['admin_dios', 'admin']:
        messages.error(request, "No tienes permiso para editar entrenadores.")
        return redirect('admin_dashboard')

    entrenador = get_object_or_404(Entrenador, fk_id_usu__pk=pk)
    usuario = entrenador.fk_id_usu

    if request.method == 'POST':
        correo_nuevo = request.POST['correo_usu']
        cedula_nueva = request.POST['cedula_usu']

        # Validación: el correo debe ser único salvo el propio usuario
        if Usuario.objects.filter(correo_usu=correo_nuevo).exclude(pk=usuario.pk).exists():
            messages.error(request, "Ya existe un usuario con ese correo.")
            return redirect('edit_entrenador', pk=pk)

        # Validación: la cédula debe ser única salvo el propio usuario
        if Usuario.objects.filter(cedula_usu=cedula_nueva).exclude(pk=usuario.pk).exists():
            messages.error(request, "Ya existe un usuario con esa cédula.")
            return redirect('edit_entrenador', pk=pk)

        usuario.correo_usu = correo_nuevo
        usuario.cedula_usu = cedula_nueva
        usuario.telefono_usu = request.POST['telefono_usu']
        usuario.nombres_usu = request.POST['nombres_usu']
        usuario.primer_apellido_usu = request.POST['primer_apellido_usu']
        usuario.segundo_apellido_usu = request.POST['segundo_apellido_usu']
        usuario.direccion_usu = request.POST['direccion_usu']
        usuario.estado_usu = request.POST['estado_usu'].lower()
        usuario.fecha_actualizacion_usu = timezone.now()
        usuario.save()
        messages.success(request, "Entrenador actualizado correctamente.")
        return redirect('list_entrenadores')

    context = {
        'entrenador': entrenador,
        'rol_usuario': request.user.rol_usu,
        'usuario': request.user
    }
    return render(request, 'Entrenador/editEntrenador.html', context)





@login_required
def delete_entrenador(request, pk):
    # Solo admins pueden eliminar
    if request.user.rol_usu not in ['admin_dios', 'admin']:
        messages.error(request, "No tienes permiso para esta acción.")
        return redirect('list_entrenadores')

    if request.method == 'POST':
        password = request.POST.get('confirm_password')
        if not request.user.check_password(password):
            messages.error(request, "Contraseña incorrecta. No se pudo eliminar.")
            return redirect('list_entrenadores')

        try:
            entrenador = get_object_or_404(Entrenador, fk_id_usu__pk=pk)
            usuario = entrenador.fk_id_usu

            # Elimina el TokenPassword si existe (opcional)
            TokenPassword.objects.filter(fk_id_usu=usuario).delete()

            # Elimina el Usuario (esto eliminará en cascada el Entrenador si tu FK tiene on_delete=CASCADE)
            usuario.delete()

            messages.success(request, "Entrenador eliminado correctamente.")
        except Exception as e:
            messages.error(request, f"Ocurrió un error inesperado: {e}")

    return redirect('list_entrenadores')



# -------------------------------CRUD CATEGORIAS-----------------------------


# Listar Categorías
@login_required
def list_categoria(request):
    if request.user.rol_usu not in ['admin_dios', 'admin']:
        messages.warning(request, "No tienes permiso para acceder aquí.")
        return redirect('admin_dashboard')

    categorias = Categoria.objects.all()
    context = {
        'categorias': categorias,
        'rol_usuario': request.user.rol_usu,
        'usuario': request.user
    }
    return render(request, 'Categoria/listCategoria.html', context)


@login_required
def add_categoria(request):
    if request.user.rol_usu not in ['admin_dios', 'admin']:
        messages.error(request, "No tienes permiso para crear categorías.")
        return redirect('admin_dashboard')

    if request.method == 'POST':
        nombre_cat = request.POST['nombre_cat'].strip().upper()
        descripcion_cat = request.POST['descripcion_cat'].strip().upper() if request.POST.get('descripcion_cat') else "SIN DESCRIPCIÓN"
        fecha_creacion_cat = timezone.now()
        fecha_actualizacion_cat = None

        # Crear y guardar la nueva categoría
        categoria = Categoria(
            nombre_cat=nombre_cat,
            descripcion_cat=descripcion_cat,
            fecha_creacion_cat=fecha_creacion_cat,
            fecha_actualizacion_cat=fecha_actualizacion_cat,
        )
        categoria.save()
        messages.success(request, f"Categoría '{nombre_cat}' creada exitosamente.")
        return redirect('list_categoria')
    
    # GET: mostrar el formulario
    return render(request, 'Categoria/addCategoria.html', {'rol_usuario': request.user.rol_usu, 'usuario': request.user})

@login_required
def edit_categoria(request, pk):
    if request.user.rol_usu not in ['admin_dios', 'admin']:
        messages.error(request, "No tienes permiso para editar categorías.")
        return redirect('list_categoria')

    categoria = get_object_or_404(Categoria, pk=pk)

    if request.method == 'POST':
        nombre_cat = request.POST.get('nombre_cat', '').strip().upper()
        descripcion_cat = request.POST.get('descripcion_cat', '').strip().upper() or "SIN DESCRIPCIÓN"
        estado_cat = request.POST.get('estado_cat', '').lower()
        categoria.nombre_cat = nombre_cat
        categoria.descripcion_cat = descripcion_cat
        categoria.estado_cat = estado_cat
        categoria.fecha_actualizacion_cat = timezone.now()
        categoria.save()
        messages.success(request, "Categoría actualizada correctamente.")
        return redirect('list_categoria')

    # GET: mostrar el formulario con los datos actuales
    return render(request, 'Categoria/editCategoria.html', {'categoria': categoria, 'rol_usuario': request.user.rol_usu, 'usuario': request.user})




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
    context = {
        'temporadas': temporadas,
        'rol_usuario': request.user.rol_usu,
        'usuario': request.user
    }
    return render(request, 'Temporada/listTemporada.html', context)


# Helper para nombre legible
def nombre_temporada_desde_fechas(fecha_inicio, fecha_fin):
    if not fecha_inicio or not fecha_fin:
        return ""
    # Ejemplo: "OCTUBRE_2025-MARZO_2026"
    inicio = timezone.datetime.strptime(fecha_inicio, "%Y-%m-%d")
    fin = timezone.datetime.strptime(fecha_fin, "%Y-%m-%d")
    nombre = f"{calendar.month_name[inicio.month].upper()}_{inicio.year}-{calendar.month_name[fin.month].upper()}_{fin.year}"
    return nombre

@login_required
def add_temporada(request):
    if request.user.rol_usu not in ['admin_dios', 'admin']:
        messages.error(request, "No tienes permiso para crear temporadas.")
        return redirect('admin_dashboard')

    if request.method == 'POST':
        fecha_inicio = request.POST.get('fecha_inicio_temp')
        fecha_fin = request.POST.get('fecha_fin_temp')
        nombre_temp = request.POST.get('nombre_temp')
        fecha_creacion_temp = timezone.now()
        fecha_actualizacion_temp = None

        if fecha_inicio and fecha_fin and fecha_fin < fecha_inicio:
            messages.error(request, "La fecha de fin no puede ser anterior a la fecha de inicio.")
            return redirect('add_temporada')

        if not nombre_temp:  # Seguridad: si el usuario manipula el JS, el backend igual lo calcula
            nombre_temp = nombre_temporada_desde_fechas(fecha_inicio, fecha_fin)

        temporada = Temporada(
            nombre_temp=nombre_temp,
            fecha_inicio_temp=fecha_inicio,
            fecha_fin_temp=fecha_fin,
            fecha_creacion_temp=fecha_creacion_temp,
            fecha_actualizacion_temp=fecha_actualizacion_temp
        )
        temporada.save()
        messages.success(request, f"Temporada '{nombre_temp}' creada exitosamente.")
        return redirect('list_temporadas')

    return render(request, 'Temporada/addTemporada.html', {'rol_usuario': request.user.rol_usu, 'usuario': request.user})


# Editar Temporada
@login_required
def edit_temporada(request, pk):
    if request.user.rol_usu not in ['admin_dios', 'admin']:
        messages.error(request, "No tienes permiso para editar temporadas.")
        return redirect('admin_dashboard')

    temporada = get_object_or_404(Temporada, pk=pk)

    if request.method == 'POST':
        fecha_inicio = request.POST.get('fecha_inicio_temp')
        fecha_fin = request.POST.get('fecha_fin_temp')
        nombre_temp = request.POST.get('nombre_temp')

        # Validación lógica: fin no puede ser antes que inicio
        if fecha_inicio and fecha_fin and fecha_fin < fecha_inicio:
            messages.error(request, "La fecha de fin no puede ser anterior a la fecha de inicio.")
            return redirect('edit_temporada', pk=pk)

        # Si el nombre no viene del form, lo generamos igual
        if not nombre_temp:
            nombre_temp = nombre_temporada_desde_fechas(fecha_inicio, fecha_fin)

        temporada.fecha_inicio_temp = fecha_inicio
        temporada.fecha_fin_temp = fecha_fin
        temporada.nombre_temp = nombre_temp
        temporada.fecha_actualizacion_temp = timezone.now()
        temporada.save()

        messages.success(request, f"Temporada '{nombre_temp}' actualizada correctamente.")
        return redirect('list_temporadas')

    return render(request, 'Temporada/editTemporada.html', {
        'temporada': temporada,
        'rol_usuario': request.user.rol_usu,
        'usuario': request.user
    })

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

    # Obtener todos los equipos con sus categorías relacionadas y el entrenador relacionado
    equipos = Equipo.objects.prefetch_related('categorias').select_related('fk_id_ent__fk_id_usu').all()

    # Agregar los IDs de las categorías asociadas a cada equipo
    for equipo in equipos:
        equipo.categorias_ids = list(equipo.categorias.values_list('id_cat', flat=True))
        # Obtener el nombre del entrenador, si existe
        if equipo.fk_id_ent:
            equipo.entrenador_nombre = equipo.fk_id_ent.fk_id_usu.nombres_usu + " " + equipo.fk_id_ent.fk_id_usu.primer_apellido_usu
        else:
            equipo.entrenador_nombre = "No asignado"

    categorias = Categoria.objects.all()

    context = {
        'equipos': equipos,
        'categorias': categorias,
        'rol_usuario': request.user.rol_usu,
        'usuario': request.user
    }

    return render(request, 'Equipo/listEquipo.html', context)





@login_required
def add_equipo(request):
    if request.user.rol_usu not in ['admin_dios', 'admin']:
        messages.error(request, "No tienes permiso para agregar equipos.")
        return redirect('admin_dashboard')

    if request.method == 'POST':
        nombre = request.POST.get('nombre_equ')
        descripcion = request.POST.get('descripcion_equ') or "SIN DESCRIPCIÓN"
        logo = request.FILES.get('logo_equ')
        fecha_fundado = request.POST.get('fecha_fundado_equ')
        fk_id_temp = request.POST.get('fk_id_temp')  # Obtener la temporada seleccionada
        fk_id_ent = request.POST.get('fk_id_ent')
        
        if not fecha_fundado:
            fecha_fundado = None
        
        categorias_ids = request.POST.getlist('categorias')
        fecha_creacion_equ = timezone.now()
        fecha_actualizacion_equ = None  # No ha sido editado aún

        # Crear el objeto Equipo
        equipo = Equipo(
            nombre_equ=nombre,
            descripcion_equ=descripcion,
            fecha_fundado_equ=fecha_fundado,
            logo_equ=logo,
            fk_id_temp=Temporada.objects.get(id_temp=fk_id_temp),  # Asignar la temporada
            fk_id_ent=Entrenador.objects.get(id_ent=fk_id_ent),  # Asignar el entrenador
            fecha_creacion_equ=fecha_creacion_equ,
            fecha_actualizacion_equ=fecha_actualizacion_equ
        )
        equipo.save()

        # Asignar las categorías seleccionadas
        if categorias_ids:
            equipo.categorias.set(categorias_ids)

        messages.success(request, "Equipo creado exitosamente.")
        return redirect('list_equipo')

    # Pasar todas las temporadas al formulario
    return render(request, 'Equipo/addEquipo.html', {
        'categorias': Categoria.objects.all(),
        'temporadas': Temporada.objects.all(),  # Pasar todas las temporadas al formulario
        'entrenadores': Entrenador.objects.all(), # Pasar todos los entrenadores al formulario
        'rol_usuario': request.user.rol_usu,
        'usuario': request.user
    })



@login_required
def edit_equipo(request, pk):
    if request.user.rol_usu not in ['admin_dios', 'admin']:
        messages.error(request, "No tienes permiso para editar equipos.")
        return redirect('list_equipo')

    # Obtener el equipo por su ID
    equipo = get_object_or_404(Equipo, pk=pk)

    # Debug: Verificar los datos del equipo
    print(f"Equipo: {equipo.nombre_equ} | Temporada: {equipo.fk_id_temp.nombre_temp}")

    if request.method == 'POST':
        equipo.nombre_equ = request.POST.get('nombre_equ')
        equipo.descripcion_equ = request.POST.get('descripcion_equ') or "SIN DESCRIPCIÓN"
        equipo.fecha_fundado_equ = request.POST.get('fecha_fundado_equ')
        equipo.fecha_actualizacion_equ = timezone.now()

        if equipo.fecha_fundado_equ == '':
            equipo.fecha_fundado_equ = None

        eliminar_logo = request.POST.get('eliminar_logo', 'false')
        nuevo_logo = request.FILES.get('logo_equ_edi')

        # Eliminar el logo si se solicita
        if eliminar_logo == 'true':
            if equipo.logo_equ:
                equipo.logo_equ.delete(save=False)  # Borra el archivo físico
            equipo.logo_equ = None

        # Si hay un nuevo logo, lo asignamos
        if nuevo_logo:
            if equipo.logo_equ:
                equipo.logo_equ.delete(save=False)
            equipo.logo_equ = nuevo_logo

        # Actualizar la temporada y el entrenador seleccionados
        fk_id_temp = request.POST.get('fk_id_temp')  # Obtener el ID de la temporada seleccionada
        fk_id_ent = request.POST.get('fk_id_ent')  # Obtener el ID del entrenador seleccionado

        if fk_id_temp:
            equipo.fk_id_temp = Temporada.objects.get(id_temp=fk_id_temp)  # Asignar la temporada

        if fk_id_ent:
            equipo.fk_id_ent = Entrenador.objects.get(id_ent=fk_id_ent)  # Asignar el entrenador

        # Actualizar las categorías asociadas
        categorias_ids = request.POST.getlist('categorias')
        equipo.categorias.set(categorias_ids)

        equipo.save()
        messages.success(request, "Equipo actualizado correctamente.")
        return redirect('list_equipo')

    # Pasamos las categorías ya asociadas
    categorias_ids = equipo.categorias.values_list('id_cat', flat=True)  # Obtener IDs de categorías asociadas
    entrenadores = Entrenador.objects.all()  # Obtener todos los entrenadores disponibles
    temporadas = Temporada.objects.all()  # Obtener todas las temporadas disponibles

    return render(request, 'Equipo/editEquipo.html', {
        'equipo': equipo,
        'categorias': Categoria.objects.all(),
        'categorias_ids': categorias_ids,  # Pasamos los IDs de las categorías ya asociadas
        'entrenadores': entrenadores,  # Pasamos todos los entrenadores disponibles
        'temporadas': temporadas,  # Pasamos todas las temporadas disponibles
        'rol_usuario': request.user.rol_usu,
        'usuario': request.user
    })


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
        'entrenadores': entrenadores,
        'rol_usuario': request.user.rol_usu,
        'usuario': request.user
    }

    return render(request, 'Jugadores/listJugadores.html', context)



@login_required
def add_jugador(request):
    # Verificar si el usuario tiene el rol adecuado
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.error(request, "No tienes permiso para crear jugadores.")
        return redirect('admin_dashboard')

    # Obtenemos los equipos y categorías disponibles
    equipos = Equipo.objects.prefetch_related('categorias').all()
    categorias = Categoria.objects.all()

    # --- NUEVO: Agrupar categorías por equipo ---
    equipo_categorias_dict = defaultdict(list)
    for equipo in equipos:
        for cat in equipo.categorias.all():
            equipo_categorias_dict[equipo.id_equ].append({'id': cat.id_cat, 'nombre': cat.nombre_cat})

    # Convertir defaultdict a diccionario normal
    equipo_categorias_dict = dict(equipo_categorias_dict)

    # Obtener el entrenador correspondiente al usuario actual
    entrenador = Entrenador.objects.filter(fk_id_usu=request.user).first()
    if not entrenador:
        messages.error(request, "Este usuario no está registrado como entrenador.")
        return redirect('list_jugadores')

    fk_id_ent_id = entrenador.id_ent

    if request.method == 'POST':
        # Datos del jugador y usuario
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
                    <a href="{enlace}" style="background-color: #28a745; color: #fff; text-decoration: none; padding: 12px 24px; font-size: 16px; border-radius: 5px; display: inline-block; font-weight: bold;">
                        Activar Cuenta
                    </a>
                </div>
                <p style="font-size: 14px; color: #999;">
                    Si no solicitaste este acceso, puedes ignorar este correo.
                </p>
                <hr style="margin-top: 40px; border: none; border-top: 1px solid #eee;">
                <p style="text-align: center; color: #ccc; font-size: 12px;">© 2025 Sistema de Entrenamientos</p>
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
        return redirect('list_jugadores')

    # Agregar al contexto de la vista
    return render(request, 'Jugadores/addJugadores.html', {
        'equipos': equipos,
        'categorias': categorias,
        'equipo_categorias_dict': equipo_categorias_dict,  # <-- Pasamos el diccionario
        'today': timezone.now(),
        'rol_usuario': request.user.rol_usu,
        'usuario': request.user
    })


@login_required
def edit_jugador(request, pk):
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.error(request, "No tienes permiso para editar jugadores.")
        return redirect('admin_dashboard')

    jugador = get_object_or_404(Jugador, pk=pk)
    usuario = jugador.fk_id_usu

    # Obtener equipos, categorías y entrenadores
    equipos = Equipo.objects.prefetch_related('categorias').all()
    categorias = Categoria.objects.all()
    entrenadores = Entrenador.objects.select_related('fk_id_usu').all()

    if request.method == 'POST':
        # Obtener datos del formulario
        nuevo_correo = request.POST['correo_usu']
        nueva_cedula = request.POST['cedula_usu']

        # Validación de unicidad de correo (solo si el correo ha cambiado)
        if nuevo_correo != usuario.correo_usu:
            if Usuario.objects.exclude(pk=usuario.pk).filter(correo_usu=nuevo_correo).exists():
                messages.error(request, "Este correo ya está registrado.")
                return redirect('edit_jugador', pk=pk)

        # Validación de unicidad de cédula (solo si la cédula ha cambiado)
        if nueva_cedula != usuario.cedula_usu:
            if Usuario.objects.exclude(pk=usuario.pk).filter(cedula_usu=nueva_cedula).exists():
                messages.error(request, "Esta cédula ya está registrada.")
                return redirect('edit_jugador', pk=pk)

        # Si las validaciones son correctas, actualizar el usuario
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

        # Actualizar la información del jugador
        jugador.fecha_nacimiento_jug = request.POST['fecha_nacimiento_jug']
        jugador.edad_jug = request.POST['edad_jug']
        jugador.peso_jug = request.POST['peso_jug']
        jugador.altura_jug = request.POST['altura_jug']
        jugador.posicion_jug = request.POST['posicion_jug']
        jugador.pie_dominante_jug = request.POST['pie_dominante_jug']
        jugador.nombre_representante_jug = request.POST['nombre_representante_jug']
        jugador.numero_emergencia_jug = request.POST['numero_emergencia_jug']
        jugador.fecha_ingreso_jug = request.POST['fecha_ingreso_jug']
        jugador.fk_id_equ_id = request.POST.get('fk_id_equ') or None
        jugador.fk_id_cat_id = request.POST.get('fk_id_cat') or None

        # Si el usuario es entrenador, asignar el entrenador relacionado
        if request.user.rol_usu == 'entrenador':
            entrenador = Entrenador.objects.filter(fk_id_usu=request.user).first()
            jugador.fk_id_ent_id = entrenador.id_ent if entrenador else None
        else:
            jugador.fk_id_ent_id = request.POST.get('fk_id_ent') or None

        jugador.fecha_actualizacion_jug = timezone.now()
        jugador.save()

        # Mensaje de éxito y redirección
        messages.success(request, "Jugador actualizado correctamente.")
        return redirect('list_jugadores')  # Redirige al listado de jugadores

    context = {
        'jugador': jugador,
        'equipos': equipos,
        'categorias': categorias,
        'entrenadores': entrenadores,
        'rol_usuario': request.user.rol_usu,
        'usuario': request.user
    }
    return render(request, 'Jugadores/editJugadores.html', context)




@login_required
def delete_jugador(request, pk):
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.error(request, "No tienes permiso para eliminar jugadores.")
        return redirect('list_jugadores')

    if request.method == 'POST':
        jugador = get_object_or_404(Jugador, pk=pk)

        # Validar si tiene relaciones protegidas
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

    return redirect('list_jugadores')


    
# -------------------------------CRUD TIPO EVALUACION Y PARAMETRO EVALUACION-------------------------------
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
        'parametros_evaluacion': parametros_evaluacion,
        'rol_usuario': request.user.rol_usu,
        'usuario': request.user
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

        # Si la descripción del tipo de evaluación está vacía, asignar "SIN DESCRIPCIÓN"
        if not descripcion_tip:
            descripcion_tip = "SIN DESCRIPCIÓN"

        # Verificar si el tipo de evaluación es cualitativo o cuantitativo
        cualitativa_tip = 'cualitativa_tip' in request.POST  # Verifica si el checkbox está marcado

        # Crear el tipo de evaluación y guardarlo en la base de datos
        tipo_evaluacion = TipoEvaluacion(
            nombre_tip=nombre_tip,
            descripcion_tip=descripcion_tip,
            fecha_creacion_tip=fecha_creacion_tip,
            estado_tip=True,  # Establecemos el estado como 'Activo' por defecto
            cualitativa_tip=cualitativa_tip  # Establecemos si es cualitativa o cuantitativa
        )
        tipo_evaluacion.save()

        # Ahora agregamos los parámetros para este tipo de evaluación
        titulos = request.POST.getlist('titulo_det[]')
        descripcion = request.POST.getlist('descripcion_det[]')

        # Recorremos los parámetros y los guardamos en la base de datos
        for titulo, desc in zip(titulos, descripcion):
            # Si el campo de descripción está vacío, asignamos "SIN DESCRIPCIÓN"
            if not desc.strip():
                desc = "SIN DESCRIPCIÓN"

            if titulo.strip() and desc.strip():
                ParametroEvaluacion.objects.create(
                    nombre_prm=titulo.strip(),
                    descripcion_prm=desc.strip(),
                    fk_tipo_evaluacion=tipo_evaluacion,
                    fecha_creacion_prm=timezone.now(),
                    estado_prm=True  # Establecemos el estado del parámetro como 'Activo' por defecto
                )

        # Mensaje de éxito y redirección
        messages.success(request, f"Tipo de Evaluación '{nombre_tip}' y sus parámetros fueron creados exitosamente.")
        return redirect('list_tipoevaluaciones')

    return render(request, 'TipoEvaluacion/addTipoEvaluaciones.html', {
        'rol_usuario': request.user.rol_usu,
        'usuario': request.user
    })


@login_required
def edit_tipoevaluacion(request, pk):
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.error(request, "No tienes permiso para editar tipos de evaluación.")
        return redirect('list_tipoevaluaciones')

    tipo_evaluacion = get_object_or_404(TipoEvaluacion, pk=pk)

    if request.method == 'POST':
        try:
            # Actualizamos los campos del tipo de evaluación
            tipo_evaluacion.nombre_tip = request.POST['nombre_tip']
            tipo_evaluacion.descripcion_tip = request.POST.get('descripcion_tip', '').strip() or "SIN DESCRIPCIÓN"
            tipo_evaluacion.estado_tip = 'estado_tip' in request.POST
            tipo_evaluacion.cualitativa_tip = 'cualitativa_tip' in request.POST
            tipo_evaluacion.fecha_actualizacion_tip = timezone.now()
            tipo_evaluacion.save()

            # Si el tipo de evaluación está desactivado, desactivamos los parámetros también
            if not tipo_evaluacion.estado_tip:
                ParametroEvaluacion.objects.filter(fk_tipo_evaluacion=tipo_evaluacion).update(estado_prm=False)

            # Recibimos los datos de los parámetros
            titulos = request.POST.getlist('titulo_det[]')
            descripciones = request.POST.getlist('descripcion_det[]')
            estados = request.POST.getlist('estado_det[]')  # AGREGAMOS ESTA LÍNEA
            ids_parametros = request.POST.getlist('detalle_id[]')

            # Validamos que todas las listas tengan la misma longitud
            max_length = max(len(titulos), len(descripciones), len(estados))
            
            # Rellenamos las listas para que tengan la misma longitud
            while len(titulos) < max_length:
                titulos.append('')
            while len(descripciones) < max_length:
                descripciones.append('')
            while len(estados) < max_length:
                estados.append('1')  # Por defecto activo
            while len(ids_parametros) < max_length:
                ids_parametros.append('')

            # Obtenemos los parámetros existentes para comparar
            parametros_existentes = ParametroEvaluacion.objects.filter(fk_tipo_evaluacion=tipo_evaluacion)
            ids_existentes = [str(p.id_prm) for p in parametros_existentes]

            # Filtramos los IDs que no están vacíos
            ids_parametros_validos = [id_param for id_param in ids_parametros if id_param and id_param != '']
            
            # Identificamos los parámetros que deben ser eliminados
            ids_eliminar = set(ids_existentes) - set(ids_parametros_validos)
            if ids_eliminar:
                ParametroEvaluacion.objects.filter(id_prm__in=ids_eliminar).delete()

            # Iteramos sobre los parámetros para actualizarlos o crearlos
            for i in range(len(titulos)):
                titulo = titulos[i].strip()
                descripcion = descripciones[i].strip() or "SIN DESCRIPCIÓN"
                estado = estados[i] == '1'  # Convertimos a boolean
                param_id = ids_parametros[i] if i < len(ids_parametros) else ''

                # Saltamos si el título está vacío
                if not titulo:
                    continue

                if param_id and param_id != '':
                    # Si el parámetro ya existe, lo actualizamos
                    parametro = ParametroEvaluacion.objects.filter(
                        id_prm=param_id,
                        fk_tipo_evaluacion=tipo_evaluacion
                    ).first()
                    if parametro:
                        parametro.nombre_prm = titulo
                        parametro.descripcion_prm = descripcion
                        parametro.estado_prm = estado
                        parametro.fecha_actualizacion_prm = timezone.now()
                        parametro.save()
                else:
                    # Si el parámetro no existe, lo creamos
                    ParametroEvaluacion.objects.create(
                        fk_tipo_evaluacion=tipo_evaluacion,
                        nombre_prm=titulo,
                        descripcion_prm=descripcion,
                        estado_prm=estado,
                        fecha_creacion_prm=timezone.now()
                    )

            # Mensaje de éxito y redirección
            messages.success(request, "Tipo de Evaluación actualizado correctamente.")
            return redirect('list_tipoevaluaciones')

        except Exception as e:
            # Si ocurre un error, mostramos el mensaje
            messages.error(request, f"Error al actualizar: {str(e)}")
            # Agregamos información de debug
            print(f"Error details: {str(e)}")
            print(f"Titulos: {request.POST.getlist('titulo_det[]')}")
            print(f"Descripciones: {request.POST.getlist('descripcion_det[]')}")
            print(f"Estados: {request.POST.getlist('estado_det[]')}")
            print(f"IDs: {request.POST.getlist('detalle_id[]')}")

    # Obtenemos los parámetros asociados a este tipo de evaluación
    parametros = tipo_evaluacion.parametroevaluacion_set.all()

    # Renderizamos la plantilla con los datos
    return render(request, 'TipoEvaluacion/editTipoEvaluaciones.html', {
        'tipo': tipo_evaluacion,
        'parametros': parametros,
        'rol_usuario': request.user.rol_usu,
        'usuario': request.user
    })


@login_required
def delete_tipoevaluacion(request, pk):
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.error(request, "No tienes permiso para esta acción.")
        return redirect('list_tipoevaluaciones')

    if request.method == 'POST':
        try:
            # Intentamos obtener el tipo de evaluación para eliminarlo
            tipo = get_object_or_404(TipoEvaluacion, pk=pk)

            # Eliminamos el tipo de evaluación
            tipo.delete()

            # Mensaje de éxito
            messages.success(request, "Tipo de Evaluación eliminado correctamente.")
        except Exception as e:
            # Si ocurre un error, mostramos el mensaje de error
            messages.error(request, f"Ocurrió un error inesperado: {e}")
            print(f"Error al eliminar tipo de evaluación: {e}")  # Mensaje en consola para depuración

        # Redirigimos a la lista de tipos de evaluación después de la eliminación
        return redirect('list_tipoevaluaciones')

    # Si no es POST, redirigimos a la lista de tipos de evaluación
    return redirect('list_tipoevaluaciones')

# ------------------------------UNIDAD ESCALA ----------------------------------

@login_required
def list_unidades(request):
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.warning(request, "No tienes permiso para acceder aquí.")
        return redirect('admin_dashboard')
    unidades = UnidadEscala.objects.all()
    return render(request, 'UnidadEscala/listUnidadEscala.html', {'unidades': unidades, 'rol_usuario': request.user.rol_usu, 'usuario': request.user})

@login_required
def add_unidad(request):
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.error(request, "No tienes permiso para crear unidades de escala.")
        return redirect('admin_dashboard')
    if request.method == 'POST':
        nombre_unes = request.POST['nombre_unes'].strip().upper()
        descripcion_unes = request.POST['descripcion_unes'].strip().upper() if request.POST.get('descripcion_unes') else "SIN DESCRIPCIÓN"
        estado_unes = True
        fecha_creacion_unes = timezone.now()
        fecha_actualizacion_unes = None
        if UnidadEscala.objects.filter(nombre_unes=nombre_unes).exists():
            messages.error(request, f"Ya existe una unidad de escala con ese nombre.")
            return redirect('add_unidad')
        unidad = UnidadEscala(
            nombre_unes=nombre_unes,
            descripcion_unes=descripcion_unes,
            estado_unes=estado_unes,
            fecha_creacion_unes=fecha_creacion_unes,
            fecha_actualizacion_unes=fecha_actualizacion_unes,
        )
        unidad.save()
        messages.success(request, f"Unidad de escala '{nombre_unes}' creada exitosamente.")
        return redirect('list_unidades')
    return render(request, 'UnidadEscala/addUnidadEscala.html', {'rol_usuario': request.user.rol_usu, 'usuario': request.user})

@login_required
def edit_unidad(request, pk):
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.error(request, "No tienes permiso para editar unidades de escala.")
        return redirect('list_unidades')
    unidad = get_object_or_404(UnidadEscala, pk=pk)
    if request.method == 'POST':
        nombre_unes = request.POST.get('nombre_unes', '').strip().upper()
        descripcion_unes = request.POST.get('descripcion_unes', '').strip().upper() or "SIN DESCRIPCIÓN"
        estado_unes = True if request.POST.get('estado_unes', 'True') == 'True' else False
        # Verificar duplicados
        if UnidadEscala.objects.exclude(pk=pk).filter(nombre_unes=nombre_unes).exists():
            messages.error(request, "Ya existe otra unidad de escala con ese nombre.")
            return redirect('edit_unidad', pk=pk)
        unidad.nombre_unes = nombre_unes
        unidad.descripcion_unes = descripcion_unes
        unidad.estado_unes = estado_unes
        unidad.fecha_actualizacion_unes = timezone.now()
        unidad.save()
        messages.success(request, "Unidad de escala actualizada correctamente.")
        return redirect('list_unidades')
    return render(request, 'UnidadEscala/editUnidadEscala.html', {'unidad': unidad, 'rol_usuario': request.user.rol_usu, 'usuario': request.user})

@login_required
def delete_unidad(request, pk):
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.error(request, "No tienes permiso para esta acción.")
        return redirect('list_unidades')
    if request.method == 'POST':
        unidad = get_object_or_404(UnidadEscala, pk=pk)
        # Aquí podrías verificar si hay rubricas asociadas antes de eliminar
        unidad.delete()
        messages.success(request, "Unidad de escala eliminada correctamente.")
    return redirect('list_unidades')



# -------------------------------RUBRICA-------------------------
@login_required
def list_rubricas(request):
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.warning(request, "No tienes permiso para acceder aquí.")
        return redirect('admin_dashboard')
    
    rubricas = Rubrica.objects.select_related('fk_id_prm', 'fk_id_cat', 'fk_id_unes').all()
    
    # Obtener parámetros únicos, sin repetir
    rubricas_unicas = []
    last_parametro = None
    
    for rubrica in rubricas:
        if rubrica.fk_id_prm != last_parametro:
            rubricas_unicas.append(rubrica)
            last_parametro = rubrica.fk_id_prm
    
    # Pasamos las rubricas únicas y el rol al contexto
    context = {
        'rubricas': rubricas_unicas,
        'rol_usuario': request.user.rol_usu,
        'usuario': request.user
    }
    
    return render(request, 'Rubrica/listRubrica.html', context)

@login_required
def view_rubrica(request, pk):
    rubrica = get_object_or_404(Rubrica, pk=pk)
    
    # Determinamos si es cualitativa o cuantitativa según el parámetro
    parametro = rubrica.fk_id_prm
    tipo_evaluacion = parametro.fk_tipo_evaluacion
    es_cualitativa = tipo_evaluacion.cualitativa_tip
    
    # Obtenemos todas las escalas de esa rúbrica
    if es_cualitativa:
        # Para rúbricas cualitativas: filtrar por parámetro y categoría solamente
        escalas = Rubrica.objects.filter(
            fk_id_prm=rubrica.fk_id_prm,
            fk_id_cat=rubrica.fk_id_cat,
            estado_rub=True,
            rubrica_cualitativa__isnull=False  # Solo las que tienen contenido cualitativo
        ).order_by('-puntaje_rub')
    else:
        # Para rúbricas cuantitativas: filtrar por parámetro, categoría y unidad
        escalas = Rubrica.objects.filter(
            fk_id_prm=rubrica.fk_id_prm,
            fk_id_cat=rubrica.fk_id_cat,
            fk_id_unes=rubrica.fk_id_unes,
            estado_rub=True,
            valor_min_rub__isnull=False,  # Solo las que tienen valores cuantitativos
            valor_max_rub__isnull=False
        ).order_by('-puntaje_rub')
    
    parametros = ParametroEvaluacion.objects.filter(estado_prm=True)
    categorias = Categoria.objects.filter(estado_cat='activo')
    unidades = UnidadEscala.objects.filter(estado_unes=True)
    
    return render(request, 'Rubrica/viewRubrica.html', {
        'rubrica': rubrica,
        'parametros': parametros,
        'categorias': categorias,
        'unidades': unidades,
        'escalas': escalas,
        'es_cualitativa': es_cualitativa,  # Pasamos esta información al template
        'rol_usuario': request.user.rol_usu,
        'usuario': request.user
    })

@login_required
def add_rubrica(request):
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.error(request, "No tienes permiso para crear rúbricas.")
        return redirect('admin_dashboard')

    # Consultas para cargar los datos en el formulario
    tipos = TipoEvaluacion.objects.filter(estado_tip=True)
    categorias = Categoria.objects.filter(estado_cat='activo')
    unidades = UnidadEscala.objects.filter(estado_unes=True)
    parametros = ParametroEvaluacion.objects.all()

    # Si el método es POST
    if request.method == 'POST':
        try:
            # Obtener los valores básicos del formulario
            fk_id_prm = request.POST['fk_id_prm']
            fk_id_cat = request.POST['fk_id_cat']
            tipo_rubrica = request.POST.get('tipo_rubrica', 'cuantitativa')
            
            # Obtener el parámetro para verificar el tipo
            parametro = ParametroEvaluacion.objects.get(pk=fk_id_prm)
            tipo_evaluacion = parametro.fk_tipo_evaluacion
            
            # Depuración
            print(f"Tipo de rúbrica: {tipo_rubrica}")
            print(f"Tipo evaluación cualitativa: {tipo_evaluacion.cualitativa_tip}")
            
            # Determinar si es cualitativa o cuantitativa basado en el tipo de evaluación
            es_cualitativa = tipo_evaluacion.cualitativa_tip
            
            # Variables para guardar
            estado_rub = True
            fecha_creacion_rub = timezone.now()
            fecha_actualizacion_rub = None
            
            if es_cualitativa:
                # RÚBRICA CUALITATIVA
                print("Procesando rúbrica cualitativa...")
                
                # Obtener los valores cualitativos
                rubricas_cualitativas = request.POST.getlist('rubrica_cualitativa[]')
                puntajes_cualitativos = request.POST.getlist('puntaje_cualitativo[]')
                
                # Filtrar valores vacíos
                rubricas_cualitativas = [r.strip() for r in rubricas_cualitativas if r.strip()]
                puntajes_cualitativos = [p for p in puntajes_cualitativos if p]
                
                print("Rúbricas cualitativas:", rubricas_cualitativas)
                print("Puntajes cualitativos:", puntajes_cualitativos)
                
                # Verificar que tenemos datos
                if not rubricas_cualitativas or not puntajes_cualitativos:
                    messages.error(request, "Por favor ingresa todos los criterios de evaluación.")
                    return redirect('add_rubrica')
                
                # Verificar que las listas tengan la misma longitud
                if len(rubricas_cualitativas) != len(puntajes_cualitativos):
                    messages.error(request, "Las listas de criterios y puntajes no coinciden en tamaño.")
                    return redirect('add_rubrica')
                
                # Guardar cada escala cualitativa
                for i in range(len(rubricas_cualitativas)):
                    Rubrica.objects.create(
                        fk_id_prm=parametro,
                        fk_id_cat=Categoria.objects.get(pk=fk_id_cat),
                        fk_id_unes=None,  # NULL para rúbricas cualitativas
                        valor_min_rub=None,  # NULL para rúbricas cualitativas
                        valor_max_rub=None,  # NULL para rúbricas cualitativas
                        rubrica_cualitativa=rubricas_cualitativas[i],
                        puntaje_rub=puntajes_cualitativos[i],
                        estado_rub=estado_rub,
                        fecha_creacion_rub=fecha_creacion_rub,
                        fecha_actualizacion_rub=fecha_actualizacion_rub
                    )
                
            else:
                # RÚBRICA CUANTITATIVA
                print("Procesando rúbrica cuantitativa...")
                
                # Obtener la unidad (requerida para rúbricas cuantitativas)
                fk_id_unes = request.POST.get('fk_id_unes')
                if not fk_id_unes:
                    messages.error(request, "Debe seleccionar una unidad de escala para rúbricas cuantitativas.")
                    return redirect('add_rubrica')
                
                # Obtener los valores cuantitativos
                valores_min = request.POST.getlist('valor_min_rub[]')
                valores_max = request.POST.getlist('valor_max_rub[]')
                puntajes = request.POST.getlist('puntaje_rub[]')
                
                # Filtrar valores vacíos
                valores_min = [v for v in valores_min if v.strip()]
                valores_max = [v for v in valores_max if v.strip()]
                puntajes = [p for p in puntajes if p.strip()]
                
                print("Valores Mínimos:", valores_min)
                print("Valores Máximos:", valores_max)
                print("Puntajes:", puntajes)
                
                # Verificar que tenemos datos
                if not valores_min or not valores_max or not puntajes:
                    messages.error(request, "Por favor ingresa todos los valores para las escalas.")
                    return redirect('add_rubrica')
                
                # Verificar que las listas tengan la misma longitud
                if len(valores_min) != len(valores_max) or len(valores_min) != len(puntajes):
                    messages.error(request, "Las listas de valores no coinciden en tamaño.")
                    return redirect('add_rubrica')
                
                # Guardar cada escala cuantitativa
                for i in range(len(valores_min)):
                    Rubrica.objects.create(
                        fk_id_prm=parametro,
                        fk_id_cat=Categoria.objects.get(pk=fk_id_cat),
                        fk_id_unes=UnidadEscala.objects.get(pk=fk_id_unes),
                        valor_min_rub=valores_min[i],
                        valor_max_rub=valores_max[i],
                        rubrica_cualitativa=None,  # NULL para rúbricas cuantitativas
                        puntaje_rub=puntajes[i],
                        estado_rub=estado_rub,
                        fecha_creacion_rub=fecha_creacion_rub,
                        fecha_actualizacion_rub=fecha_actualizacion_rub
                    )
            
            # Mensaje de éxito
            messages.success(request, "Rúbrica creada correctamente.")
            return redirect('list_rubricas')

        except KeyError as e:
            # Error por campos faltantes
            messages.error(request, f"Campo requerido faltante: {str(e)}")
            return redirect('add_rubrica')
        except ValueError as e:
            # Error de valor inválido
            messages.error(request, f"Valor inválido: {str(e)}")
            return redirect('add_rubrica')
        except Exception as e:
            # Error general
            messages.error(request, f"Hubo un error: {str(e)}")
            print(f"Error completo: {e}")
            return redirect('add_rubrica')

    # Renderizar la vista
    return render(request, 'Rubrica/addRubrica.html', {
        'tipos': tipos,
        'categorias': categorias,
        'unidades': unidades,
        'parametros': parametros,
        'rol_usuario': request.user.rol_usu,
        'usuario': request.user
    })


@login_required
def ajax_parametros_por_tipo(request):
    tipo_id = request.GET.get('tipo_id')
    parametros = []
    cualitativa = False
    if tipo_id:
        tipo = TipoEvaluacion.objects.get(pk=tipo_id)
        cualitativa = tipo.cualitativa_tip  # Obtenemos el valor del campo cualitativa_tip
        parametros_qs = ParametroEvaluacion.objects.filter(
            fk_tipo_evaluacion_id=tipo_id,
            estado_prm=True
        )
        parametros = [
            {'id_prm': p.id_prm, 'nombre_prm': p.nombre_prm}
            for p in parametros_qs
        ]
    return JsonResponse({
        'parametros': parametros,
        'cualitativa': cualitativa  # Retornamos este valor
    })



@login_required
def edit_rubrica(request, pk):
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.error(request, "No tienes permiso para editar rúbricas.")
        return redirect('admin_dashboard')

    rubrica = get_object_or_404(Rubrica, pk=pk)
    
    # Determinamos si es cualitativa o cuantitativa según el parámetro
    parametro = rubrica.fk_id_prm
    tipo_evaluacion = parametro.fk_tipo_evaluacion
    es_cualitativa = tipo_evaluacion.cualitativa_tip
    
    # Obtenemos todas las escalas de esa rúbrica
    if es_cualitativa:
        # Para rúbricas cualitativas: filtrar por parámetro y categoría solamente
        escalas = Rubrica.objects.filter(
            fk_id_prm=rubrica.fk_id_prm,
            fk_id_cat=rubrica.fk_id_cat,
            estado_rub=True,
            rubrica_cualitativa__isnull=False  # Solo las que tienen contenido cualitativo
        ).order_by('-puntaje_rub')
    else:
        # Para rúbricas cuantitativas: filtrar por parámetro, categoría y unidad
        escalas = Rubrica.objects.filter(
            fk_id_prm=rubrica.fk_id_prm,
            fk_id_cat=rubrica.fk_id_cat,
            fk_id_unes=rubrica.fk_id_unes,
            estado_rub=True,
            valor_min_rub__isnull=False,  # Solo las que tienen valores cuantitativos
            valor_max_rub__isnull=False
        ).order_by('-puntaje_rub')
    
    # Consultas para cargar los datos en el formulario
    tipos = TipoEvaluacion.objects.filter(estado_tip=True)
    parametros = ParametroEvaluacion.objects.filter(estado_prm=True)
    categorias = Categoria.objects.filter(estado_cat='activo')
    unidades = UnidadEscala.objects.filter(estado_unes=True)

    if request.method == 'POST':
        try:
            # Obtener los valores básicos del formulario
            fk_id_prm = request.POST['fk_id_prm']
            fk_id_cat = request.POST['fk_id_cat']
            tipo_rubrica = request.POST.get('tipo_rubrica', 'cuantitativa')
            
            # Obtener el parámetro para verificar el tipo
            parametro_nuevo = ParametroEvaluacion.objects.get(pk=fk_id_prm)
            tipo_evaluacion_nuevo = parametro_nuevo.fk_tipo_evaluacion
            
            # Determinar si es cualitativa o cuantitativa basado en el tipo de evaluación
            es_cualitativa_nuevo = tipo_evaluacion_nuevo.cualitativa_tip
            
            # Variables para guardar
            estado_rub = True
            fecha_actualizacion_rub = timezone.now()
            
            # Eliminar todas las escalas anteriores de ese grupo
            if es_cualitativa:
                # Eliminar rúbricas cualitativas anteriores
                Rubrica.objects.filter(
                    fk_id_prm=rubrica.fk_id_prm,
                    fk_id_cat=rubrica.fk_id_cat,
                    estado_rub=True,
                    rubrica_cualitativa__isnull=False
                ).delete()
            else:
                # Eliminar rúbricas cuantitativas anteriores
                Rubrica.objects.filter(
                    fk_id_prm=rubrica.fk_id_prm,
                    fk_id_cat=rubrica.fk_id_cat,
                    fk_id_unes=rubrica.fk_id_unes,
                    estado_rub=True,
                    valor_min_rub__isnull=False,
                    valor_max_rub__isnull=False
                ).delete()
            
            if es_cualitativa_nuevo:
                # RÚBRICA CUALITATIVA
                print("Procesando rúbrica cualitativa en edición...")
                
                # Obtener los valores cualitativos
                rubricas_cualitativas = request.POST.getlist('rubrica_cualitativa[]')
                puntajes_cualitativos = request.POST.getlist('puntaje_cualitativo[]')
                
                # Filtrar valores vacíos
                rubricas_cualitativas = [r.strip() for r in rubricas_cualitativas if r.strip()]
                puntajes_cualitativos = [p for p in puntajes_cualitativos if p]
                
                # Verificar que tenemos datos
                if not rubricas_cualitativas or not puntajes_cualitativos:
                    messages.error(request, "Por favor ingresa todos los criterios de evaluación.")
                    return redirect('edit_rubrica', pk=pk)
                
                # Verificar que las listas tengan la misma longitud
                if len(rubricas_cualitativas) != len(puntajes_cualitativos):
                    messages.error(request, "Las listas de criterios y puntajes no coinciden en tamaño.")
                    return redirect('edit_rubrica', pk=pk)
                
                # Guardar cada escala cualitativa
                for i in range(len(rubricas_cualitativas)):
                    Rubrica.objects.create(
                        fk_id_prm=parametro_nuevo,
                        fk_id_cat=Categoria.objects.get(pk=fk_id_cat),
                        fk_id_unes=None,  # NULL para rúbricas cualitativas
                        valor_min_rub=None,  # NULL para rúbricas cualitativas
                        valor_max_rub=None,  # NULL para rúbricas cualitativas
                        rubrica_cualitativa=rubricas_cualitativas[i],
                        puntaje_rub=puntajes_cualitativos[i],
                        estado_rub=estado_rub,
                        fecha_creacion_rub=timezone.now(),  # Nueva fecha de creación
                        fecha_actualizacion_rub=fecha_actualizacion_rub
                    )
                
            else:
                # RÚBRICA CUANTITATIVA
                print("Procesando rúbrica cuantitativa en edición...")
                
                # Obtener la unidad (requerida para rúbricas cuantitativas)
                fk_id_unes = request.POST.get('fk_id_unes')
                if not fk_id_unes:
                    messages.error(request, "Debe seleccionar una unidad de escala para rúbricas cuantitativas.")
                    return redirect('edit_rubrica', pk=pk)
                
                # Obtener los valores cuantitativos
                valores_min = request.POST.getlist('valor_min_rub[]')
                valores_max = request.POST.getlist('valor_max_rub[]')
                puntajes = request.POST.getlist('puntaje_rub[]')
                
                # Filtrar valores vacíos
                valores_min = [v for v in valores_min if v.strip()]
                valores_max = [v for v in valores_max if v.strip()]
                puntajes = [p for p in puntajes if p.strip()]
                
                # Verificar que tenemos datos
                if not valores_min or not valores_max or not puntajes:
                    messages.error(request, "Por favor ingresa todos los valores para las escalas.")
                    return redirect('edit_rubrica', pk=pk)
                
                # Verificar que las listas tengan la misma longitud
                if len(valores_min) != len(valores_max) or len(valores_min) != len(puntajes):
                    messages.error(request, "Las listas de valores no coinciden en tamaño.")
                    return redirect('edit_rubrica', pk=pk)
                
                # Guardar cada escala cuantitativa
                for i in range(len(valores_min)):
                    Rubrica.objects.create(
                        fk_id_prm=parametro_nuevo,
                        fk_id_cat=Categoria.objects.get(pk=fk_id_cat),
                        fk_id_unes=UnidadEscala.objects.get(pk=fk_id_unes),
                        valor_min_rub=valores_min[i],
                        valor_max_rub=valores_max[i],
                        rubrica_cualitativa=None,  # NULL para rúbricas cuantitativas
                        puntaje_rub=puntajes[i],
                        estado_rub=estado_rub,
                        fecha_creacion_rub=timezone.now(),  # Nueva fecha de creación
                        fecha_actualizacion_rub=fecha_actualizacion_rub
                    )
            
            # Mensaje de éxito
            messages.success(request, "Rúbrica actualizada correctamente.")
            return redirect('list_rubricas')

        except KeyError as e:
            # Error por campos faltantes
            messages.error(request, f"Campo requerido faltante: {str(e)}")
            return redirect('edit_rubrica', pk=pk)
        except ValueError as e:
            # Error de valor inválido
            messages.error(request, f"Valor inválido: {str(e)}")
            return redirect('edit_rubrica', pk=pk)
        except Exception as e:
            # Error general
            messages.error(request, f"Hubo un error: {str(e)}")
            print(f"Error completo: {e}")
            return redirect('edit_rubrica', pk=pk)

    return render(request, 'Rubrica/editRubrica.html', {
        'rubrica': rubrica,
        'tipos': tipos,
        'parametros': parametros,
        'categorias': categorias,
        'unidades': unidades,
        'escalas': escalas,
        'es_cualitativa': es_cualitativa,  # Pasamos esta información al template
        'rol_usuario': request.user.rol_usu,
        'usuario': request.user
    })


@login_required
def delete_rubrica(request, pk):
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.error(request, "No tienes permiso para esta acción.")
        return redirect('list_rubricas')
    if request.method == 'POST':
        # 1. Buscar la rúbrica base para identificar el grupo
        rubrica = get_object_or_404(Rubrica, pk=pk)
        # 2. Eliminar todas las escalas que pertenezcan al mismo grupo (param, cat, unidad)
        Rubrica.objects.filter(
            fk_id_prm=rubrica.fk_id_prm,
            fk_id_cat=rubrica.fk_id_cat,
            fk_id_unes=rubrica.fk_id_unes,
            estado_rub=True
        ).delete()
        messages.success(request, "Rúbrica eliminada correctamente.")
    return redirect('list_rubricas')


#-----------------------------CRUD PRUEBA --------------------------------
@login_required
def list_pruebas(request):
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.warning(request, "No tienes permiso para acceder aquí.")
        return redirect('admin_dashboard')

    pruebas = Prueba.objects.select_related(
        'fk_id_ent__fk_id_usu',  # entrenador.usuario
        'fk_id_jug__fk_id_usu',  # jugador.usuario
        'fk_id_tip',
        'fk_id_temp',
        'fk_id_ciclo'
    ).all().order_by('-fecha_pru', '-id_pru')

    return render(request, 'Prueba/listPrueba.html', {
        'pruebas': pruebas,
        'rol_usuario': request.user.rol_usu,
        'usuario': request.user
    })
@login_required
def detalle_prueba(request, id_pru):
    from django.shortcuts import get_object_or_404
    prueba = get_object_or_404(
        Prueba.objects.select_related(
            'fk_id_ent__fk_id_usu',
            'fk_id_jug__fk_id_usu',
            'fk_id_tip',
            'fk_id_temp'
        ),
        pk=id_pru
    )
    detalles = prueba.detalles.select_related('fk_id_prm').all()
    return render(request, 'Prueba/detallePrueba.html', {
        'prueba': prueba,
        'detalles': detalles,
        'usuario': request.user,
        'rol_usuario': request.user.rol_usu,
    })




# agregar pruebas
# views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse


@login_required
def add_prueba(request):
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.error(request, "No tienes permiso para crear pruebas.")
        return redirect('admin_dashboard')

    # Filtra jugadores SOLO del equipo del entrenador logueado
    if request.user.rol_usu == 'entrenador':
        entrenador = Entrenador.objects.filter(fk_id_usu=request.user).first()
        if entrenador:
            equipos = Equipo.objects.filter(fk_id_ent=entrenador)
            jugadores = Jugador.objects.select_related('fk_id_cat', 'fk_id_usu').filter(fk_id_equ__in=equipos)
        else:
            jugadores = Jugador.objects.none()
    else:
        jugadores = Jugador.objects.select_related('fk_id_cat', 'fk_id_usu').all()

    tipos = TipoEvaluacion.objects.filter(estado_tip=True)
    temporadas = Temporada.objects.all()
    ciclos = CicloDeEntrenamiento.objects.all()
    hoy = timezone.now().date().isoformat()

    valores = {
        'fk_id_jug': request.POST.get('fk_id_jug') or '',
        'fk_id_tip': request.POST.get('fk_id_tip') or '',
        'fk_id_temp': request.POST.get('fk_id_temp') or '',
        'fk_id_ciclo': request.POST.get('fk_id_ciclo') or '',
        'fecha_pru': request.POST.get('fecha_pru') or hoy,
        'observaciones_pru': request.POST.get('observaciones_pru') or '',
    }

    if request.method == 'POST' and request.POST.get('guardar') == '1':
        fk_id_jug = request.POST.get('fk_id_jug')
        fk_id_tip = request.POST.get('fk_id_tip')
        fk_id_temp = request.POST.get('fk_id_temp')
        fk_id_ciclo = request.POST.get('fk_id_ciclo')
        fecha_pru = request.POST.get('fecha_pru')
        observaciones_pru = request.POST.get('observaciones_pru')

        parametros_ids = request.POST.getlist('fk_id_prm[]')
        valores_observados = request.POST.getlist('valor_observado[]')
        unidades = request.POST.getlist('unidad[]')
        notas_calculadas = request.POST.getlist('nota_calculada[]')

        # Validar que tengamos datos
        if not parametros_ids or not valores_observados or not notas_calculadas:
            messages.error(request, "Faltan datos en el formulario.")
            return redirect('add_prueba')

        # Obtener el tipo de evaluación para verificar si es cualitativo
        tipo_evaluacion = TipoEvaluacion.objects.get(pk=fk_id_tip)
        es_cualitativo = tipo_evaluacion.cualitativa_tip

        # Procesar las notas calculadas
        notas_float = []
        for nota in notas_calculadas:
            if nota != '' and nota is not None:
                try:
                    notas_float.append(float(nota))
                except ValueError:
                    messages.error(request, "Error en el cálculo de las notas.")
                    return redirect('add_prueba')

        promedio_pru = round(sum(notas_float) / len(notas_float), 2) if notas_float else 0

        entrenador = None
        if request.user.rol_usu == 'entrenador':
            entrenador = Entrenador.objects.filter(fk_id_usu=request.user).first()
            if not entrenador:
                messages.error(request, "No tienes un perfil de entrenador asociado. Contacta al administrador.")
                return redirect('add_prueba')

        try:
            # Crear la prueba
            prueba = Prueba.objects.create(
                fk_id_ent=entrenador,  # Si es admin/admin_dios será None
                fk_id_jug_id=fk_id_jug,
                fk_id_tip_id=fk_id_tip,
                fk_id_temp_id=fk_id_temp,
                fk_id_ciclo_id=fk_id_ciclo,
                promedio_pru=promedio_pru,
                observaciones_pru=observaciones_pru,
                fecha_pru=fecha_pru,
                estado_pru=True,
            )
            
            # Crear los detalles de la prueba
            for i, (id_prm, val_obs, unidad, nota) in enumerate(zip(parametros_ids, valores_observados, unidades, notas_calculadas)):
                # Validar que el valor observado no esté vacío
                if not val_obs:
                    continue
                
                # Validar que la nota calculada no esté vacía
                if not nota:
                    continue
                
                # El valor observado puede ser texto (cualitativo) o número (cuantitativo)
                # Lo guardamos como texto en el campo TextField
                DetallePrueba.objects.create(
                    fk_id_pru=prueba,
                    fk_id_prm_id=id_prm,
                    valor_observado=str(val_obs),  # Convertir a string para almacenamiento
                    unidad=unidad if not es_cualitativo else '',  # Sin unidad para cualitativo
                    nota_calculada=float(nota),  # Convertir a float para la nota
                )
            
            # Actualizar el promedio del jugador
            actualizar_promedio_jugador(
                jugador=prueba.fk_id_jug,
                ciclo=prueba.fk_id_ciclo,
                tipo=prueba.fk_id_tip,
                temporada=prueba.fk_id_temp
            )
            
            messages.success(request, "Prueba registrada correctamente. Promedio: %.2f" % promedio_pru)
            return redirect('list_pruebas')
            
        except Exception as e:
            messages.error(request, f"Ocurrió un error al guardar la prueba: {e}")
            return redirect('add_prueba')

    return render(request, 'Prueba/addPrueba.html', {
        'jugadores': jugadores,
        'tipos': tipos,
        'temporadas': temporadas,
        'ciclos': ciclos,
        'valores': valores,
        'hoy': hoy,
        'rol_usuario': request.user.rol_usu,
        'usuario': request.user,
    })


@login_required
def ajax_parametros_rubrica(request):
    tipo_id = request.GET.get('tipo')
    jug_id = request.GET.get('jug')
    if not (tipo_id and jug_id):
        return JsonResponse({'parametros': [], 'tienen_todas_rubrica': True})

    # Obtener el jugador y su categoría
    jugador = Jugador.objects.get(pk=jug_id)
    cat_id = jugador.fk_id_cat_id if jugador.fk_id_cat else None
    
    # Obtener el tipo de evaluación para verificar si es cualitativo
    tipo_evaluacion = TipoEvaluacion.objects.get(pk=tipo_id)
    es_cualitativo = tipo_evaluacion.cualitativa_tip
    
    # Obtener los parámetros del tipo de evaluación
    parametros = ParametroEvaluacion.objects.filter(fk_tipo_evaluacion_id=tipo_id, estado_prm=True)
    parametros_data = []
    todas_tienen_rubrica = True
    
    for prm in parametros:
        if es_cualitativo:
            # Para evaluaciones cualitativas, obtenemos las rúbricas cualitativas
            rubricas = list(Rubrica.objects.filter(
                fk_id_prm=prm, 
                fk_id_cat_id=cat_id, 
                estado_rub=True,
                rubrica_cualitativa__isnull=False  # Solo las que tienen criterio cualitativo
            ).values('rubrica_cualitativa', 'puntaje_rub'))
            
            # La unidad no aplica para evaluaciones cualitativas
            unidad = ''
        else:
            # Para evaluaciones cuantitativas, obtenemos las rúbricas cuantitativas
            rubricas = list(Rubrica.objects.filter(
                fk_id_prm=prm, 
                fk_id_cat_id=cat_id, 
                estado_rub=True,
                valor_min_rub__isnull=False,  # Solo las que tienen valores numéricos
                valor_max_rub__isnull=False
            ).values('valor_min_rub', 'valor_max_rub', 'puntaje_rub', 'fk_id_unes__nombre_unes'))
            
            # Para evaluaciones cuantitativas, obtenemos la unidad
            unidad = rubricas[0]['fk_id_unes__nombre_unes'] if rubricas else ''
        
        # Verificar si el parámetro tiene rúbrica
        if not rubricas:
            todas_tienen_rubrica = False
        
        parametros_data.append({
            'id_prm': prm.id_prm,
            'nombre_prm': prm.nombre_prm,
            'unidad': unidad,
            'rubricas': rubricas,
            'es_cualitativo': es_cualitativo,  # Nueva propiedad para indicar el tipo
        })
    
    return JsonResponse({
        'parametros': parametros_data, 
        'tienen_todas_rubrica': todas_tienen_rubrica
    })

# editar
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.utils import timezone
from django.contrib.auth.decorators import login_required
import json
from django.core.serializers.json import DjangoJSONEncoder
import datetime

@login_required
def edit_prueba(request, id_pru):
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.error(request, "No tienes permiso para editar pruebas.")
        return redirect('list_pruebas')

    from .models import Prueba, Jugador, TipoEvaluacion, Temporada, DetallePrueba, Rubrica, Equipo, Entrenador

    prueba = get_object_or_404(
        Prueba.objects.select_related(
            'fk_id_ent__fk_id_usu',
            'fk_id_jug__fk_id_usu',
            'fk_id_tip',
            'fk_id_ciclo',
            'fk_id_temp'
        ),
        pk=id_pru
    )

    # Solo jugadores de su equipo si es entrenador
    if request.user.rol_usu == 'entrenador':
        entrenador = Entrenador.objects.filter(fk_id_usu=request.user).first()
        equipos = Equipo.objects.filter(fk_id_ent=entrenador)
        jugadores = Jugador.objects.select_related('fk_id_usu', 'fk_id_cat').filter(fk_id_equ__in=equipos)
    else:
        jugadores = Jugador.objects.select_related('fk_id_usu', 'fk_id_cat').all()

    tipos = TipoEvaluacion.objects.filter(estado_tip=True)
    temporadas = Temporada.objects.all()
    ciclos = CicloDeEntrenamiento.objects.all()

    # Prepara detalles con rubricas_json para cada parámetro
    detalles = prueba.detalles.select_related('fk_id_prm').all()
    for det in detalles:
        cat_id = prueba.fk_id_jug.fk_id_cat_id if prueba.fk_id_jug and prueba.fk_id_jug.fk_id_cat_id else None
        rubricas = Rubrica.objects.filter(
            fk_id_prm=det.fk_id_prm_id,
            fk_id_cat_id=cat_id,
            estado_rub=True
        ).values('valor_min_rub', 'valor_max_rub', 'puntaje_rub')
        det.rubricas_json = json.dumps(list(rubricas), cls=DjangoJSONEncoder) if rubricas else "[]"

    if request.method == 'POST' and request.POST.get('guardar') == '1':
        fk_id_jug = request.POST.get('fk_id_jug')
        fk_id_tip = request.POST.get('fk_id_tip')
        fk_id_temp = request.POST.get('fk_id_temp')
        fk_id_ciclo = request.POST.get('fk_id_ciclo')
        fecha_pru = request.POST.get('fecha_pru')
        observaciones_pru = request.POST.get('observaciones_pru')

        parametros_ids = request.POST.getlist('fk_id_prm[]')
        valores_observados = request.POST.getlist('valor_observado[]')
        unidades = request.POST.getlist('unidad[]')
        notas_calculadas = request.POST.getlist('nota_calculada[]')

        notas_float = [float(v) for v in notas_calculadas if v not in ('', None)]
        promedio_pru = round(sum(notas_float) / len(notas_float), 2) if notas_float else 0

        try:
            # Actualizar prueba
            prueba.fk_id_jug_id = fk_id_jug
            prueba.fk_id_tip_id = fk_id_tip
            prueba.fk_id_temp_id = fk_id_temp
            prueba.fk_id_ciclo_id = fk_id_ciclo
            prueba.promedio_pru = promedio_pru
            prueba.observaciones_pru = observaciones_pru

            # Corrige la fecha: pasa a tipo date si viene en str
            if fecha_pru:
                if isinstance(fecha_pru, str):
                    prueba.fecha_pru = datetime.datetime.strptime(fecha_pru, "%Y-%m-%d").date()
                else:
                    prueba.fecha_pru = fecha_pru
            else:
                prueba.fecha_pru = None

            prueba.fecha_actualizacion_pru = timezone.now()
            prueba.save()

            # Eliminar detalles viejos y crear nuevos
            prueba.detalles.all().delete()
            for id_prm, val_obs, unidad, nota in zip(parametros_ids, valores_observados, unidades, notas_calculadas):
                DetallePrueba.objects.create(
                    fk_id_pru=prueba,
                    fk_id_prm_id=id_prm,
                    valor_observado=val_obs,
                    unidad=unidad,
                    nota_calculada=nota,
                )
            # LLAMA LA FUNCION PARA GUARDAR/ACTUALIZAR PROMEDIOJUGADOR
            actualizar_promedio_jugador(
                jugador=prueba.fk_id_jug,
                ciclo=prueba.fk_id_ciclo,
                tipo=prueba.fk_id_tip,
                temporada=prueba.fk_id_temp
            )
            messages.success(request, "Prueba actualizada correctamente.")
            return redirect('list_pruebas')
        except Exception as e:
            messages.error(request, f"Ocurrió un error al actualizar la prueba: {e}")

    # Prepara valores iniciales para el formulario
    fecha_pru_val = ''
    if prueba.fecha_pru:
        if isinstance(prueba.fecha_pru, str):
            fecha_pru_val = prueba.fecha_pru
        elif isinstance(prueba.fecha_pru, (datetime.date, datetime.datetime)):
            fecha_pru_val = prueba.fecha_pru.isoformat()

    valores = {
        'fk_id_jug': prueba.fk_id_jug_id,
        'fk_id_tip': prueba.fk_id_tip_id,
        'fk_id_temp': prueba.fk_id_temp_id,
        'fk_id_ciclo': prueba.fk_id_ciclo_id,

        'fecha_pru': fecha_pru_val,
        'observaciones_pru': prueba.observaciones_pru or '',
    }

    return render(request, 'Prueba/editPrueba.html', {
        'prueba': prueba,
        'detalles': detalles,
        'jugadores': jugadores,
        'tipos': tipos,
        'temporadas': temporadas,
        'ciclos': ciclos,
        'valores': valores,
        'rol_usuario': request.user.rol_usu,
        'usuario': request.user,
    })

@login_required
def delete_prueba(request, id_pru):
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.error(request, "No tienes permiso para eliminar pruebas.")
        return redirect('list_pruebas')

    from .models import Prueba, DetallePrueba

    prueba = get_object_or_404(Prueba, pk=id_pru)

    # Elimina detalles primero (por si la relación no es cascade)
    DetallePrueba.objects.filter(fk_id_pru=prueba).delete()
    prueba.delete()

    messages.success(request, "Prueba y sus detalles eliminados correctamente.")
    return redirect('list_pruebas')





# ----------------------------------------------notas equipo-------------------------------------------

def actualizar_promedio_jugador(jugador, ciclo, tipo, temporada):
    from .models import Prueba, PromedioJugador, TipoEvaluacion
    # Busca todas las pruebas de este jugador, macro, tipo, temporada (puede haber varias si se repite)
    pruebas = Prueba.objects.filter(
        fk_id_jug=jugador,
        fk_id_ciclo=ciclo,
        fk_id_tip=tipo,
        fk_id_temp=temporada
    )
    if pruebas.exists():
        promedio = sum([float(p.promedio_pru) for p in pruebas if p.promedio_pru is not None]) / pruebas.count()
        promedio = round(promedio, 2)
    else:
        promedio = 0.0
    # Guarda o actualiza el promedio
    PromedioJugador.objects.update_or_create(
        jugador_proju=jugador,
        fk_id_ciclo=ciclo,
        tipo_proju=tipo,
        temporada_proju=temporada,
        defaults={'promedio_proju': promedio}
    )

from .models import PromedioJugador

@login_required
def promedios_jugadores_equipo(request):
    user = request.user
    temporadas = Temporada.objects.all()
    temporada_id = request.GET.get('temporada')  # Puede ser vacío
    ciclo_id = request.GET.get('ciclo')  # Puede ser vacío
    jugador_id = request.GET.get('jugador')  # Nuevo filtro por jugador
    tipos = TipoEvaluacion.objects.filter(estado_tip=True)
    equipo = None
    jugadores = []
    equipo_nombre = "Sin equipo"
    ciclos = CicloDeEntrenamiento.objects.all()

    # Obtener temporada seleccionada (puede ser None)
    temporada = None
    if temporada_id:
        try:
            temporada = Temporada.objects.get(id_temp=temporada_id)
        except Temporada.DoesNotExist:
            temporada = None

    # Obtener jugadores según el rol del usuario
    todos_jugadores = []  # Lista completa para el select
    if user.rol_usu == 'entrenador':
        entrenador = Entrenador.objects.filter(fk_id_usu=user).first()
        if entrenador:
            # Si hay temporada seleccionada, filtrar por esa temporada
            if temporada:
                equipo = Equipo.objects.filter(fk_id_ent=entrenador, fk_id_temp=temporada).first()
            else:
                # Si no hay temporada, obtener el primer equipo del entrenador
                equipo = Equipo.objects.filter(fk_id_ent=entrenador).first()
            
            if equipo:
                equipo_nombre = equipo.nombre_equ or "Sin nombre"
                todos_jugadores = Jugador.objects.filter(fk_id_equ=equipo)
            else:
                todos_jugadores = []
    else:
        equipo_nombre = "Todos los equipos"
        todos_jugadores = Jugador.objects.all()

    # Filtrar jugadores según selección
    if jugador_id and jugador_id != 'todos':
        try:
            jugadores = todos_jugadores.filter(id_jug=jugador_id)
        except:
            jugadores = todos_jugadores
    else:
        jugadores = todos_jugadores

    # Filtrar ciclos según selección
    ciclos_filtrados = ciclos  # Por defecto todos los ciclos
    if ciclo_id and ciclo_id != 'ambos':
        try:
            ciclos_filtrados = CicloDeEntrenamiento.objects.filter(id_ciclo=ciclo_id)
        except:
            ciclos_filtrados = ciclos

    # Buscar promedios guardados con filtros opcionales
    datos = []
    for jugador in jugadores:
        for ciclo in ciclos_filtrados:
            # Crear filtro base para PromedioJugador
            filtro_promedio = {
                'jugador_proju': jugador,
                'fk_id_ciclo': ciclo,
            }
            
            # Agregar filtro de temporada solo si está seleccionada
            if temporada:
                filtro_promedio['temporada_proju_id'] = temporada.id_temp

            fila = {
                'jugador': jugador,
                'ciclo': ciclo,
                'tipos': [],
                'promedio_general': "0.00",
            }
            
            promedios_tipo = []
            tiene_datos = False
            
            for tipo in tipos:
                filtro_promedio['tipo_proju'] = tipo
                promedio_obj = PromedioJugador.objects.filter(
                    **filtro_promedio
                ).order_by('-fecha_calculo_proju').first()
                
                nota = promedio_obj.promedio_proju if promedio_obj else 0
                if promedio_obj:
                    tiene_datos = True
                    
                fila['tipos'].append({
                    'tipo': tipo.nombre_tip,
                    'nota': f"{nota:.2f}"
                })
                promedios_tipo.append(float(nota))
            
            # Solo agregar la fila si tiene datos o si no hay filtros aplicados
            if tiene_datos or (not temporada_id and not ciclo_id and not jugador_id):
                fila['promedio_general'] = f"{(sum(promedios_tipo)/len(promedios_tipo)):.2f}" if promedios_tipo else "0.00"
                datos.append(fila)

    context = {
        'temporadas': temporadas,
        'temporada_actual': temporada.id_temp if temporada else '',
        'tipos': tipos,
        'datos': datos,
        'equipo_nombre': equipo_nombre,
        'ciclo_id': ciclo_id if ciclo_id else 'ambos',
        'ciclos': ciclos,
        'jugador_id': jugador_id if jugador_id else 'todos',
        'jugadores': todos_jugadores  # Para el select de jugadores
    }
    return render(request, 'Notas/promedios_guardados_equipo.html', context)

@login_required
def get_parametros(request, evaluacion_id):
    parametros = ParametroEvaluacion.objects.filter(fk_tipo_evaluacion_id=evaluacion_id)
    parametros_data = [
        {"id": parametro.id, "titulo": parametro.nombre_prm}
        for parametro in parametros
    ]
    return JsonResponse(parametros_data, safe=False)





#-------------------------------------CICLOS-------------------------------------
@login_required
def list_ciclo(request):
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.warning(request, "No tienes permiso para acceder aquí.")
        return redirect('admin_dashboard')

    ciclos = CicloDeEntrenamiento.objects.all()
    context = {
        'ciclos': ciclos,
        'rol_usuario': request.user.rol_usu,
        'usuario': request.user
    }
    return render(request, 'Ciclo/listCiclo.html', context)

@login_required
def add_ciclo(request):
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.error(request, "No tienes permiso para crear ciclos.")
        return redirect('admin_dashboard')

    if request.method == 'POST':
        # Forzar que el nombre del ciclo sea en mayúsculas antes de guardar
        nombre_ciclo = request.POST['nombre_ciclo'].strip().upper()  # Cambiado a .upper()
        estado_ciclo = True
        fecha_creacion_ciclo = timezone.now()
        fecha_actualizacion_ciclo = None

        # Crear y guardar el nuevo ciclo
        ciclo = CicloDeEntrenamiento(
            nombre_ciclo=nombre_ciclo,
            estado_ciclo=estado_ciclo,
            fecha_creacion_ciclo=fecha_creacion_ciclo,
            fecha_actualizacion_ciclo=fecha_actualizacion_ciclo,
        )
        ciclo.save()
        messages.success(request, f"Ciclo '{nombre_ciclo}' creado exitosamente.")
        return redirect('list_ciclo')

    return render(request, 'Ciclo/addCiclo.html', {'rol_usuario': request.user.rol_usu, 'usuario': request.user})

@login_required
def edit_ciclo(request, pk):
    if request.user.rol_usu not in ['admin_dios', 'admin', 'entrenador']:
        messages.error(request, "No tienes permiso para editar ciclos.")
        return redirect('list_ciclo')

    ciclo = get_object_or_404(CicloDeEntrenamiento, pk=pk)

    if request.method == 'POST':
        # Forzar mayúsculas en el nombre del ciclo
        ciclo.nombre_ciclo = request.POST['nombre_ciclo'].strip().upper()  # Cambiado a .upper()
        ciclo.estado_ciclo = request.POST.get('estado_ciclo', False)
        ciclo.fecha_actualizacion_ciclo = timezone.now()
        ciclo.save()
        messages.success(request, "Ciclo actualizado correctamente.")
        return redirect('list_ciclo')

    return render(request, 'Ciclo/editCiclo.html', {'ciclo': ciclo, 'rol_usuario': request.user.rol_usu, 'usuario': request.user})



@login_required
def delete_ciclo(request, pk):
    if request.user.rol_usu not in ['admin_dios', 'admin']:
        messages.error(request, "No tienes permiso para esta acción.")
        return redirect('list_ciclo')

    if request.method == 'POST':
        try:
            # Intentamos obtener la ciclo a eliminar
            ciclo = get_object_or_404(CicloDeEntrenamiento, pk=pk)

            ciclo.delete()
            messages.success(request, "Ciclo eliminado correctamente.")
        except Exception as e:
            messages.error(request, f"Ocurrió un error inesperado: {e}")

    return redirect('list_ciclo')


#DASHBOARD

# Si quieres redirigir al usuario después de iniciar sesión, usa esta vista:



#------------------------------ DASHBOARD ADMIN-------------------------------------
# views.py
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db import models
from django.db.models import Avg, Count, Q, Max
from django.utils import timezone
from datetime import datetime, timedelta
import json
from collections import defaultdict

# Asegúrate de importar tus modelos
# from .models import Usuario, Entrenador, Jugador, Equipo, Prueba, TipoEvaluacion, CicloDeEntrenamiento, Temporada, Categoria

@login_required
def dashboard_admin(request):
    # Verificar que el usuario sea administrador
    if request.user.rol_usu != 'admin':
        messages.error(request, "No tienes permisos para acceder a esta página.")
        return redirect('admin_dashboard')

    # Estadísticas básicas
    total_jugadores = Jugador.objects.filter(fk_id_usu__estado_usu='activo').count()
    total_equipos = Equipo.objects.count()
    total_entrenadores = Entrenador.objects.filter(fk_id_usu__estado_usu='activo').count()
    total_pruebas = Prueba.objects.count()

    # Datos para gráficas
    rendimiento_jugador = get_rendimiento_jugador_admin()
    valoracion_equipos = get_valoracion_equipos_admin()
    ultimos_ingresos = get_ultimos_ingresos_admin()
    top5_general = get_top5_general_admin()
    distribucion_categorias = get_distribucion_categorias_admin()
    evaluaciones_tipo = get_evaluaciones_tipo_admin()
    rendimiento_temporada = get_rendimiento_temporada_admin()
    actividad_reciente = get_actividad_reciente_admin()

    # Resumen de equipos
    resumen_equipos = get_resumen_equipos_admin()

    # Últimas pruebas realizadas
    ultimas_pruebas = Prueba.objects.select_related(
        'fk_id_jug__fk_id_usu',
        'fk_id_jug__fk_id_equ',
        'fk_id_tip',
        'fk_id_ent__fk_id_usu'
    ).order_by('-fecha_pru')[:10]

    context = {
        'usuario': request.user,
        'total_jugadores': total_jugadores,
        'total_equipos': total_equipos,
        'total_entrenadores': total_entrenadores,
        'total_pruebas': total_pruebas,
        'rol_usuario': request.user.rol_usu,
        
        # Datos para gráficas (convertidos a JSON)
        'rendimiento_jugador': json.dumps(rendimiento_jugador),
        'valoracion_equipos': json.dumps(valoracion_equipos),
        'ultimos_ingresos': json.dumps(ultimos_ingresos),
        'top5_general': json.dumps(top5_general),
        'distribucion_categorias': json.dumps(distribucion_categorias),
        'evaluaciones_tipo': json.dumps(evaluaciones_tipo),
        'rendimiento_temporada': json.dumps(rendimiento_temporada),
        'actividad_reciente': json.dumps(actividad_reciente),
        
        # Datos para tablas
        'resumen_equipos': resumen_equipos,
        'ultimas_pruebas': ultimas_pruebas,
    }

    return render(request, 'Dashboard/dashboard_admin.html', context )


def get_rendimiento_jugador_admin():
    """
    Obtiene el rendimiento promedio de los top 10 jugadores del sistema
    """
    # Obtener jugadores activos con su promedio de pruebas
    jugadores_promedio = Prueba.objects.filter(
        fk_id_jug__fk_id_usu__estado_usu='activo'
    ).values(
        'fk_id_jug__fk_id_usu__nombres_usu',
        'fk_id_jug__fk_id_usu__primer_apellido_usu'
    ).annotate(
        promedio=models.Avg('promedio_pru')
    ).order_by('-promedio')[:10]
    
    labels = []
    data = []
    
    for jugador in jugadores_promedio:
        nombre_completo = f"{jugador['fk_id_jug__fk_id_usu__nombres_usu']} {jugador['fk_id_jug__fk_id_usu__primer_apellido_usu']}"
        labels.append(nombre_completo)
        data.append(float(jugador['promedio']) if jugador['promedio'] else 0)
    
    return {
        'labels': labels,
        'data': data
    }


def get_valoracion_equipos_admin():
    """
    Obtiene la valoración promedio por equipos
    """
    equipos_promedio = Prueba.objects.filter(
        fk_id_jug__fk_id_equ__isnull=False
    ).values(
        'fk_id_jug__fk_id_equ__nombre_equ'
    ).annotate(
        promedio=models.Avg('promedio_pru')
    ).order_by('-promedio')
    
    labels = []
    data = []
    
    for equipo in equipos_promedio:
        labels.append(equipo['fk_id_jug__fk_id_equ__nombre_equ'])
        data.append(float(equipo['promedio']) if equipo['promedio'] else 0)
    
    return {
        'labels': labels,
        'data': data
    }


def get_ultimos_ingresos_admin():
    """
    Obtiene los ingresos de entrenadores en los últimos 30 días
    """
    fecha_inicio = timezone.now().date() - timedelta(days=30)
    
    # Obtener el número de entrenadores que han ingresado por día
    ingresos = Entrenador.objects.filter(
        fk_id_usu__last_login__gte=fecha_inicio
    ).values(
        'fk_id_usu__last_login__date'
    ).annotate(
        total=Count('id_ent')
    ).order_by('fk_id_usu__last_login__date')
    
    labels = []
    data = []
    
    for ingreso in ingresos:
        if ingreso['fk_id_usu__last_login__date']:
            labels.append(ingreso['fk_id_usu__last_login__date'].strftime('%d/%m'))
            data.append(ingreso['total'])
    
    return {
        'labels': labels,
        'data': data
    }


def get_top5_general_admin():
    """
    Obtiene los top 5 jugadores con mejor rendimiento general
    """
    top_jugadores = Prueba.objects.values(
        'fk_id_jug__fk_id_usu__nombres_usu',
        'fk_id_jug__fk_id_usu__primer_apellido_usu'
    ).annotate(
        promedio=models.Avg('promedio_pru')
    ).order_by('-promedio')[:5]
    
    labels = []
    data = []
    
    for jugador in top_jugadores:
        nombre_completo = f"{jugador['fk_id_jug__fk_id_usu__nombres_usu']} {jugador['fk_id_jug__fk_id_usu__primer_apellido_usu']}"
        labels.append(nombre_completo)
        data.append(float(jugador['promedio']) if jugador['promedio'] else 0)
    
    return {
        'labels': labels,
        'data': data
    }


def get_distribucion_categorias_admin():
    """
    Obtiene la distribución de equipos por categorías
    """
    try:
        # Obtener equipos por categoría
        categorias = Categoria.objects.annotate(
            total_equipos=Count('equipos')
        ).filter(total_equipos__gt=0)
        
        labels = []
        data = []
        
        for categoria in categorias:
            labels.append(categoria.nombre_cat)
            data.append(categoria.total_equipos)
        
        return {
            'labels': labels,
            'data': data
        }
    except:
        # Si no existe el modelo Categoria o hay error
        return {
            'labels': ['Sin categorías'],
            'data': [0]
        }


def get_evaluaciones_tipo_admin():
    """
    Obtiene el número de evaluaciones por tipo
    """
    tipos_evaluacion = TipoEvaluacion.objects.annotate(
        total_pruebas=Count('prueba')
    ).filter(total_pruebas__gt=0)
    
    labels = []
    data = []
    
    for tipo in tipos_evaluacion:
        labels.append(tipo.nombre_tip)
        data.append(tipo.total_pruebas)
    
    return {
        'labels': labels,
        'data': data
    }


def get_rendimiento_temporada_admin():
    """
    Obtiene el rendimiento promedio por temporada
    """
    temporadas = Temporada.objects.annotate(
        promedio=models.Avg('prueba__promedio_pru')
    ).filter(promedio__isnull=False).order_by('fecha_inicio_temp')
    
    labels = []
    data = []
    
    for temporada in temporadas:
        labels.append(temporada.nombre_temp)
        data.append(float(temporada.promedio) if temporada.promedio else 0)
    
    return {
        'labels': labels,
        'data': data
    }


def get_actividad_reciente_admin():
    """
    Obtiene la actividad reciente del sistema (pruebas por día en los últimos 7 días)
    """
    fecha_inicio = timezone.now().date() - timedelta(days=7)
    
    actividad = Prueba.objects.filter(
        fecha_pru__gte=fecha_inicio
    ).values('fecha_pru').annotate(
        total=Count('id_pru')
    ).order_by('fecha_pru')
    
    labels = []
    data = []
    
    for dia in actividad:
        labels.append(dia['fecha_pru'].strftime('%d/%m'))
        data.append(dia['total'])
    
    return {
        'labels': labels,
        'data': data
    }


def get_resumen_equipos_admin():
    """
    Obtiene el resumen detallado de todos los equipos
    """
    equipos = Equipo.objects.select_related(
        'fk_id_ent__fk_id_usu'
    ).prefetch_related('categorias').annotate(
        total_jugadores=Count('jugador', filter=Q(jugador__fk_id_usu__estado_usu='activo')),
        promedio_general=models.Avg('jugador__prueba__promedio_pru'),
        ultima_evaluacion=Max('jugador__prueba__fecha_pru')
    )
    
    return equipos

#------------------------------ DASHBOARD ENTRENADOR-------------------------------------

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db import models
from django.db.models import Avg, Count, Q
from django.utils import timezone
from datetime import datetime, timedelta
import json
from collections import defaultdict
@login_required
def dashboard_entrenador(request):
    # Obtener el entrenador logueado
    try:
        entrenador = Entrenador.objects.get(fk_id_usu=request.user)
    except Entrenador.DoesNotExist:
        messages.error(request, "No se encontró el entrenador asociado a este usuario.")
        return redirect('admin_dashboard')

    # Obtener el equipo asociado al entrenador
    equipo = Equipo.objects.filter(fk_id_ent=entrenador).first()
    if equipo is None:
        messages.error(request, "Este entrenador no tiene un equipo asignado.")
        return redirect('admin_dashboard')

    # Datos básicos
    jugadores_activos = Jugador.objects.filter(
        fk_id_equ=equipo, 
        fk_id_usu__estado_usu='activo'
    ).count()
    
    pruebas_realizadas = Prueba.objects.filter(fk_id_ent=entrenador).count()
    
    promedio_general = Prueba.objects.filter(
        fk_id_ent=entrenador
    ).aggregate(promedio=models.Avg('promedio_pru'))['promedio'] or 0
    
    ultimas_pruebas = Prueba.objects.filter(
        fk_id_ent=entrenador
    ).order_by('-fecha_pru')[:5]

    # KPI 1: Rendimiento por Jugador (Top 5)
    rendimiento_jugadores = get_rendimiento_por_jugador(entrenador)
    
    # KPI 2: Rendimiento por Mesociclo
    rendimiento_mesociclo = get_rendimiento_por_mesociclo(entrenador)
    
    # KPI 3: Rendimiento por Temporada
    rendimiento_temporada = get_rendimiento_por_temporada(entrenador)
    
    # KPI 4: Valoración General (por tipo de evaluación)
    valoracion_general = get_valoracion_general(entrenador)
    
    # KPI 5: Últimos Ingresos (pruebas por fecha)
    ultimos_ingresos = get_ultimos_ingresos(entrenador)
    
    # Datos adicionales para el dashboard
    pruebas_mes = Prueba.objects.filter(
        fk_id_ent=entrenador,
        fecha_pru__month=timezone.now().month,
        fecha_pru__year=timezone.now().year
    ).count()
    
    mejor_jugador = get_mejor_jugador(entrenador)
    temporada_actual = get_temporada_actual()

    context = {
        'equipo': equipo,
        'jugadores_activos': jugadores_activos,
        'pruebas_realizadas': pruebas_realizadas,
        'promedio_general': promedio_general,
        'ultimas_pruebas': ultimas_pruebas,
        'usuario': request.user,
        'rol_usuario': request.user.rol_usu,
        
        # Datos para gráficas (convertidos a JSON)
        'rendimiento_jugadores': json.dumps(rendimiento_jugadores),
        'rendimiento_mesociclo': json.dumps(rendimiento_mesociclo),
        'rendimiento_temporada': json.dumps(rendimiento_temporada),
        'valoracion_general': json.dumps(valoracion_general),
        'ultimos_ingresos': json.dumps(ultimos_ingresos),
        
        # Datos adicionales
        'pruebas_mes': pruebas_mes,
        'mejor_jugador': mejor_jugador,
        'temporada_actual': temporada_actual,
    }

    return render(request, 'Dashboard/dashboard_entrenador.html', context)


def get_rendimiento_por_jugador(entrenador):
    """
    Obtiene el rendimiento promedio de los top 5 jugadores
    """
    # Obtener jugadores del equipo del entrenador
    jugadores = Jugador.objects.filter(
        fk_id_equ__fk_id_ent=entrenador,
        fk_id_usu__estado_usu='activo'
    )
    
    rendimiento_data = []
    
    for jugador in jugadores:
        promedio = Prueba.objects.filter(
            fk_id_jug=jugador,
            fk_id_ent=entrenador
        ).aggregate(promedio=models.Avg('promedio_pru'))['promedio']
        
        if promedio:
            rendimiento_data.append({
                'jugador': f"{jugador.fk_id_usu.nombres_usu} {jugador.fk_id_usu.primer_apellido_usu}",
                'promedio': float(promedio)
            })
    
    # Ordenar por promedio y tomar top 5
    rendimiento_data.sort(key=lambda x: x['promedio'], reverse=True)
    top_5 = rendimiento_data[:5]
    
    return {
        'labels': [item['jugador'] for item in top_5],
        'data': [item['promedio'] for item in top_5]
    }


def get_rendimiento_por_mesociclo(entrenador):
    """
    Obtiene el rendimiento promedio por mesociclo
    """
    # Obtener todos los mesociclos con pruebas
    mesociclos = CicloDeEntrenamiento.objects.filter(
        prueba__fk_id_ent=entrenador
    ).distinct().order_by('nombre_ciclo')
    
    labels = []
    data = []
    
    for mesociclo in mesociclos:
        promedio = Prueba.objects.filter(
            fk_id_ent=entrenador,
            fk_id_ciclo=mesociclo
        ).aggregate(promedio=models.Avg('promedio_pru'))['promedio']
        
        if promedio:
            labels.append(mesociclo.nombre_ciclo or f"Ciclo {mesociclo.id_ciclo}")
            data.append(float(promedio))
    
    return {
        'labels': labels,
        'data': data
    }


def get_rendimiento_por_temporada(entrenador):
    """
    Obtiene el rendimiento promedio por temporada
    """
    temporadas = Temporada.objects.filter(
        prueba__fk_id_ent=entrenador
    ).distinct()
    
    labels = []
    data = []
    
    for temporada in temporadas:
        promedio = Prueba.objects.filter(
            fk_id_ent=entrenador,
            fk_id_temp=temporada
        ).aggregate(promedio=models.Avg('promedio_pru'))['promedio']
        
        if promedio:
            labels.append(temporada.nombre_temp or f"Temporada {temporada.id_temp}")
            data.append(float(promedio))
    
    return {
        'labels': labels,
        'data': data
    }


def get_valoracion_general(entrenador):
    """
    Obtiene la valoración general por tipo de evaluación
    """
    tipos_evaluacion = TipoEvaluacion.objects.filter(
        prueba__fk_id_ent=entrenador
    ).distinct()
    
    labels = []
    data = []
    
    for tipo in tipos_evaluacion:
        promedio = Prueba.objects.filter(
            fk_id_ent=entrenador,
            fk_id_tip=tipo
        ).aggregate(promedio=models.Avg('promedio_pru'))['promedio']
        
        if promedio:
            labels.append(tipo.nombre_tip)
            data.append(float(promedio))
    
    return {
        'labels': labels,
        'data': data
    }


def get_ultimos_ingresos(entrenador):
    """
    Obtiene las pruebas realizadas en los últimos 30 días agrupadas por fecha
    """
    fecha_inicio = timezone.now().date() - timedelta(days=30)
    
    # Obtener pruebas de los últimos 30 días
    pruebas = Prueba.objects.filter(
        fk_id_ent=entrenador,
        fecha_pru__gte=fecha_inicio
    ).values('fecha_pru').annotate(
        total=Count('id_pru')
    ).order_by('fecha_pru')
    
    labels = []
    data = []
    
    for prueba in pruebas:
        labels.append(prueba['fecha_pru'].strftime('%d/%m'))
        data.append(prueba['total'])
    
    return {
        'labels': labels,
        'data': data
    }


def get_mejor_jugador(entrenador):
    """
    Obtiene el jugador con mejor promedio general
    """
    mejor = Prueba.objects.filter(
        fk_id_ent=entrenador
    ).values(
        'fk_id_jug__fk_id_usu__nombres_usu',
        'fk_id_jug__fk_id_usu__primer_apellido_usu'
    ).annotate(
        promedio=models.Avg('promedio_pru')
    ).order_by('-promedio').first()
    
    if mejor:
        return f"{mejor['fk_id_jug__fk_id_usu__nombres_usu']} {mejor['fk_id_jug__fk_id_usu__primer_apellido_usu']}"
    
    return "N/A"


def get_temporada_actual():
    """
    Obtiene la temporada actual
    """
    temporada_actual = Temporada.objects.filter(
        fecha_inicio_temp__lte=timezone.now().date(),
        fecha_fin_temp__gte=timezone.now().date()
    ).first()
    
    if temporada_actual:
        return temporada_actual.nombre_temp
    
    # Si no hay temporada actual, obtener la más reciente
    temporada_reciente = Temporada.objects.order_by('-fecha_inicio_temp').first()
    return temporada_reciente.nombre_temp if temporada_reciente else "N/A"


# Función adicional para obtener estadísticas detalladas por jugador
def get_estadisticas_jugador(jugador_id, entrenador):
    """
    Obtiene estadísticas detalladas de un jugador específico
    """
    try:
        jugador = Jugador.objects.get(id_jug=jugador_id, fk_id_ent=entrenador)
        
        # Promedio general del jugador
        promedio_general = Prueba.objects.filter(
            fk_id_jug=jugador,
            fk_id_ent=entrenador
        ).aggregate(promedio=models.Avg('promedio_pru'))['promedio'] or 0
        
        # Número de pruebas realizadas
        total_pruebas = Prueba.objects.filter(
            fk_id_jug=jugador,
            fk_id_ent=entrenador
        ).count()
        
        # Última prueba
        ultima_prueba = Prueba.objects.filter(
            fk_id_jug=jugador,
            fk_id_ent=entrenador
        ).order_by('-fecha_pru').first()
        
        # Evolución en los últimos 6 meses
        fecha_inicio = timezone.now().date() - timedelta(days=180)
        evolucion = Prueba.objects.filter(
            fk_id_jug=jugador,
            fk_id_ent=entrenador,
            fecha_pru__gte=fecha_inicio
        ).values('fecha_pru').annotate(
            promedio=models.Avg('promedio_pru')
        ).order_by('fecha_pru')
        
        return {
            'jugador': jugador,
            'promedio_general': float(promedio_general),
            'total_pruebas': total_pruebas,
            'ultima_prueba': ultima_prueba,
            'evolucion': list(evolucion)
        }
        
    except Jugador.DoesNotExist:
        return None

#------------------------------ DASHBOARD JUGADOR-------------------------------------

# Importaciones necesarias para el dashboard del jugador
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib import messages
from django.db import models
from django.utils import timezone
from django.db.models import Count, Avg
from django.db.models.functions import TruncMonth
from datetime import timedelta
import json


@login_required
def dashboard_jugador(request):
    # Obtener el jugador logueado
    try:
        jugador = Jugador.objects.get(fk_id_usu=request.user)
    except Jugador.DoesNotExist:
        messages.error(request, "No se encontró el jugador asociado a este usuario.")
        return redirect('admin_dashboard')

    # Datos básicos del jugador
    total_pruebas = Prueba.objects.filter(fk_id_jug=jugador).count()
    
    promedio_personal = Prueba.objects.filter(
        fk_id_jug=jugador
    ).aggregate(promedio=models.Avg('promedio_pru'))['promedio'] or 0
    
    # Obtener posición en el equipo
    posicion_equipo = get_posicion_en_equipo(jugador)
    
    # Última evaluación
    ultima_evaluacion_obj = Prueba.objects.filter(
        fk_id_jug=jugador
    ).order_by('-fecha_pru').first()
    
    ultima_evaluacion = ultima_evaluacion_obj.promedio_pru if ultima_evaluacion_obj else 0
    
    # Mis últimas 5 pruebas
    mis_ultimas_pruebas = Prueba.objects.filter(
        fk_id_jug=jugador
    ).order_by('-fecha_pru')[:5]

    # KPI 1: Rendimiento personal por tipo de evaluación
    rendimiento_personal = get_rendimiento_personal_por_tipo(jugador)
    
    # KPI 2: Evolución del rendimiento personal
    evolucion_rendimiento = get_evolucion_rendimiento_personal(jugador)
    
    # KPI 3: Valoración general del equipo
    valoracion_equipo = get_valoracion_equipo_jugador(jugador)
    
    # KPI 4: Top 5 jugadores del equipo
    top5_jugadores = get_top5_jugadores_equipo(jugador)
    
    # KPI 5: Comparación con promedio del equipo
    comparacion_equipo = get_comparacion_con_equipo(jugador)
    
    # KPI 6: Últimas evaluaciones del jugador
    ultimas_evaluaciones = get_ultimas_evaluaciones_jugador(jugador)

    context = {
        'usuario': request.user,
        'jugador': jugador,
        'total_pruebas': total_pruebas,
        'promedio_personal': promedio_personal,
        'posicion_equipo': posicion_equipo,
        'ultima_evaluacion': ultima_evaluacion,
        'mis_ultimas_pruebas': mis_ultimas_pruebas,
        'rol_usuario': request.user.rol_usu,
        
        # Datos para gráficas (convertidos a JSON)
        'rendimiento_personal': json.dumps(rendimiento_personal),
        'evolucion_rendimiento': json.dumps(evolucion_rendimiento),
        'valoracion_equipo': json.dumps(valoracion_equipo),
        'top5_jugadores': json.dumps(top5_jugadores),
        'comparacion_equipo': json.dumps(comparacion_equipo),
        'ultimas_evaluaciones': json.dumps(ultimas_evaluaciones),
    }

    return render(request, 'Dashboard/dashboard_jugador.html', context)


def get_posicion_en_equipo(jugador):
    """
    Obtiene la posición del jugador en el ranking del equipo
    """
    # Obtener todos los jugadores del mismo equipo con sus promedios
    jugadores_equipo = Jugador.objects.filter(
        fk_id_equ=jugador.fk_id_equ,
        fk_id_usu__estado_usu='activo'
    ).annotate(
        promedio_general=models.Avg('prueba__promedio_pru')
    ).order_by('-promedio_general')
    
    # Encontrar la posición del jugador actual
    for posicion, jug in enumerate(jugadores_equipo, 1):
        if jug.id_jug == jugador.id_jug:
            return posicion
    
    return 0


def get_rendimiento_personal_por_tipo(jugador):
    """
    Obtiene el rendimiento personal por tipo de evaluación
    """
    tipos_evaluacion = TipoEvaluacion.objects.filter(
        prueba__fk_id_jug=jugador
    ).distinct()
    
    labels = []
    data = []
    
    for tipo in tipos_evaluacion:
        promedio = Prueba.objects.filter(
            fk_id_jug=jugador,
            fk_id_tip=tipo
        ).aggregate(promedio=models.Avg('promedio_pru'))['promedio']
        
        if promedio:
            labels.append(tipo.nombre_tip)
            data.append(float(promedio))
    
    return {
        'labels': labels,
        'data': data
    }


def get_evolucion_rendimiento_personal(jugador):
    """
    Obtiene la evolución del rendimiento personal en los últimos 6 meses
    """
    fecha_inicio = timezone.now().date() - timedelta(days=180)
    
    # Obtener pruebas agrupadas por mes
    pruebas_por_mes = Prueba.objects.filter(
        fk_id_jug=jugador,
        fecha_pru__gte=fecha_inicio
    ).annotate(
        mes=TruncMonth('fecha_pru')
    ).values('mes').annotate(
        promedio=models.Avg('promedio_pru')
    ).order_by('mes')
    
    labels = []
    data = []
    
    for registro in pruebas_por_mes:
        labels.append(registro['mes'].strftime('%B %Y'))
        data.append(float(registro['promedio']))
    
    return {
        'labels': labels,
        'data': data
    }


def get_valoracion_equipo_jugador(jugador):
    """
    Obtiene la valoración general del equipo por tipo de evaluación
    """
    tipos_evaluacion = TipoEvaluacion.objects.filter(
        prueba__fk_id_jug__fk_id_equ=jugador.fk_id_equ
    ).distinct()
    
    labels = []
    data = []
    
    for tipo in tipos_evaluacion:
        promedio = Prueba.objects.filter(
            fk_id_jug__fk_id_equ=jugador.fk_id_equ,
            fk_id_tip=tipo
        ).aggregate(promedio=models.Avg('promedio_pru'))['promedio']
        
        if promedio:
            labels.append(tipo.nombre_tip)
            data.append(float(promedio))
    
    return {
        'labels': labels,
        'data': data
    }


def get_top5_jugadores_equipo(jugador):
    """
    Obtiene el top 5 de jugadores del equipo
    """
    jugadores_equipo = Jugador.objects.filter(
        fk_id_equ=jugador.fk_id_equ,
        fk_id_usu__estado_usu='activo'
    ).annotate(
        promedio_general=models.Avg('prueba__promedio_pru')
    ).order_by('-promedio_general')[:5]
    
    labels = []
    data = []
    colors = []
    
    # Colores para destacar al jugador actual
    color_jugador_actual = 'rgba(255, 99, 132, 0.8)'  # Rojo
    color_otros = 'rgba(54, 162, 235, 0.8)'  # Azul
    
    for jug in jugadores_equipo:
        nombre = f"{jug.fk_id_usu.nombres_usu} {jug.fk_id_usu.primer_apellido_usu}"
        labels.append(nombre)
        data.append(float(jug.promedio_general or 0))
        
        # Destacar al jugador actual
        if jug.id_jug == jugador.id_jug:
            colors.append(color_jugador_actual)
        else:
            colors.append(color_otros)
    
    return {
        'labels': labels,
        'data': data,
        'colors': colors
    }


def get_comparacion_con_equipo(jugador):
    """
    Compara el rendimiento del jugador con el promedio del equipo por tipo de evaluación
    """
    tipos_evaluacion = TipoEvaluacion.objects.filter(
        prueba__fk_id_jug=jugador
    ).distinct()
    
    labels = []
    mi_rendimiento = []
    promedio_equipo = []
    
    for tipo in tipos_evaluacion:
        # Promedio personal
        promedio_personal = Prueba.objects.filter(
            fk_id_jug=jugador,
            fk_id_tip=tipo
        ).aggregate(promedio=models.Avg('promedio_pru'))['promedio']
        
        # Promedio del equipo
        promedio_equipo_tipo = Prueba.objects.filter(
            fk_id_jug__fk_id_equ=jugador.fk_id_equ,
            fk_id_tip=tipo
        ).aggregate(promedio=models.Avg('promedio_pru'))['promedio']
        
        if promedio_personal and promedio_equipo_tipo:
            labels.append(tipo.nombre_tip)
            mi_rendimiento.append(float(promedio_personal))
            promedio_equipo.append(float(promedio_equipo_tipo))
    
    return {
        'labels': labels,
        'mi_rendimiento': mi_rendimiento,
        'promedio_equipo': promedio_equipo
    }


def get_ultimas_evaluaciones_jugador(jugador):
    """
    Obtiene las últimas 10 evaluaciones del jugador
    """
    ultimas_pruebas = Prueba.objects.filter(
        fk_id_jug=jugador
    ).order_by('-fecha_pru')[:10]
    
    labels = []
    data = []
    
    for prueba in ultimas_pruebas:
        labels.append(prueba.fecha_pru.strftime('%d/%m'))
        data.append(float(prueba.promedio_pru))
    
    # Invertir para mostrar cronológicamente
    labels.reverse()
    data.reverse()
    
    return {
        'labels': labels,
        'data': data
    }


# Función adicional para obtener estadísticas detalladas del jugador
def get_estadisticas_detalladas_jugador(jugador):
    """
    Obtiene estadísticas detalladas del jugador
    """
    # Promedio por temporada
    promedios_temporada = Prueba.objects.filter(
        fk_id_jug=jugador
    ).values(
        'fk_id_temp__nombre_temp'
    ).annotate(
        promedio=models.Avg('promedio_pru')
    ).order_by('-fk_id_temp__fecha_inicio_temp')
    
    # Promedio por mesociclo
    promedios_mesociclo = Prueba.objects.filter(
        fk_id_jug=jugador
    ).values(
        'fk_id_ciclo__nombre_ciclo'
    ).annotate(
        promedio=models.Avg('promedio_pru')
    ).order_by('-fecha_pru')
    
    # Mejor y peor evaluación
    mejor_evaluacion = Prueba.objects.filter(
        fk_id_jug=jugador
    ).order_by('-promedio_pru').first()
    
    peor_evaluacion = Prueba.objects.filter(
        fk_id_jug=jugador
    ).order_by('promedio_pru').first()
    
    return {
        'promedios_temporada': list(promedios_temporada),
        'promedios_mesociclo': list(promedios_mesociclo),
        'mejor_evaluacion': mejor_evaluacion,
        'peor_evaluacion': peor_evaluacion
    }

