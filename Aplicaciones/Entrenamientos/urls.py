from django.urls import path
from . import views


urlpatterns = [
    path('', views.index, name='index'),
    path('login/', views.CustomLoginView.as_view(), name='login'),
    path('logout/', views.CustomLogoutView,           name='logout'),

    # -------------------------------VALIDACION EN BDD-----------------------------
    path('validate_cedula/', views.validate_cedula, name='validate_cedula'),
    path('validate_correo/', views.validate_correo, name='validate_correo'),

    # -------------------------------MENU PRINCIPAL-----------------------------
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),

    # -------------------------------MANEJO DE TOKENS-----------------------------
    # Activación vía token
    path('activar-contrasena/<str:token>/', views.crear_contrasena, name='activar_contrasena'),
    # Recuperar contraseña
    path('password_reset_request/', views.password_reset_request, name='password_reset_request'),
    path('password_reset_confirm/<str:token>/', views.password_reset_confirm, name='password_reset_confirm'),

    # -------------------------------CRUD ADMINISTRADORES-----------------------------
    path('admins/', views.list_admins, name='list_admins'),
    path('admins/add/', views.add_admin, name='add_admin'),
    path('admins/edit/<int:pk>/', views.edit_admin, name='edit_admin'),
    path('admins/delete/<int:pk>/', views.delete_admin, name='delete_admin'),

    # -------------------------------CRUD ENTRENADORES-----------------------------
    path('entrenadores/', views.list_entrenadores, name='list_entrenadores'),
    path('entrenadores/add/', views.add_entrenador, name='add_entrenador'),
    path('entrenadores/edit/<int:pk>/', views.edit_entrenador, name='edit_entrenador'),
    path('entrenadores/delete/<int:pk>/', views.delete_entrenador, name='delete_entrenador'),

    # -------------------------------CRUD CATEGORIAS-----------------------------
    path('categorias/', views.list_categoria, name='list_categoria'),
    path('categorias/add/', views.add_categoria, name='add_categoria'),
    path('categorias/edit/<int:pk>/', views.edit_categoria, name='edit_categoria'),
    path('categorias/delete/<int:pk>/', views.delete_categoria, name='delete_categoria'),

    # -------------------------------CRUD TEMPORADAS-----------------------------
    path('temporadas/', views.list_temporadas, name='list_temporadas'),
    path('temporadas/add/', views.add_temporada, name='add_temporada'),
    path('temporadas/edit/<int:pk>/', views.edit_temporada, name='edit_temporada'),
    path('temporadas/delete/<int:pk>/', views.delete_temporada, name='delete_temporada'),

    # -------------------------------CRUD EQUIPOS-----------------------------
    path('equipos/', views.list_equipo, name='list_equipo'),
    path('equipos/add/', views.add_equipo, name='add_equipo'),
    path('equipos/edit/<int:pk>/', views.edit_equipo, name='edit_equipo'),
    path('equipos/delete/<int:pk>/', views.delete_equipo, name='delete_equipo'),

    # -------------------------------CRUD JUGADORES-----------------------------
    path('jugadores/', views.list_jugadores, name='list_jugadores'),
    path('jugadores/add/', views.add_jugador, name='add_jugador'),
    path('jugadores/editar/', views.edit_jugador, name='edit_jugador'),
    path('jugadores/delete/<int:pk>/', views.delete_jugador, name='delete_jugador'),

    

]