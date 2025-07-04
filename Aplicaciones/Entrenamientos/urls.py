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
    path('jugadores/editar/<int:pk>/', views.edit_jugador, name='edit_jugador'),
    path('jugadores/delete/<int:pk>/', views.delete_jugador, name='delete_jugador'),

    # -------------------------------CRUD EVALUACIONES-----------------------------
    path('tipos_evaluaciones/', views.list_tipoevaluaciones, name='list_tipoevaluaciones'),
    path('tipos_evaluaciones/add/', views.add_tipoevaluacion, name='add_tipoevaluacion'),
    path('api/get_parametros/<int:evaluacion_id>/', views.get_parametros, name='get_parametros'),
    path('tipos_evaluaciones/edit/<int:pk>/', views.edit_tipoevaluacion, name='edit_tipoevaluacion'),
    path('tipos_evaluaciones/delete/<int:pk>/', views.delete_tipoevaluacion, name='delete_tipoevaluacion'),


    # ------------------------------CRUD UNIDADES ESCALA-------------------------
    path('unidades/', views.list_unidades, name='list_unidades'),
    path('unidades/add/', views.add_unidad, name='add_unidad'),
    path('unidades/edit/<int:pk>/', views.edit_unidad, name='edit_unidad'),
    path('unidades/delete/<int:pk>/', views.delete_unidad, name='delete_unidad'),

    #-----------------------------------CRUD RUBRICAS-------------------------
    path('rubricas/', views.list_rubricas, name='list_rubricas'),
    path('rubricas/view/<int:pk>/', views.view_rubrica, name='view_rubrica'),
    path('rubricas/add/', views.add_rubrica, name='add_rubrica'),
    path('ajax/parametros_por_tipo/', views.ajax_parametros_por_tipo, name='ajax_parametros_por_tipo'),
    path('rubricas/edit/<int:pk>/', views.edit_rubrica, name='edit_rubrica'),
    path('rubricas/delete/<int:pk>/', views.delete_rubrica, name='delete_rubrica'),


    #------------------------------------------CRUD PRUEBAS ---------------------------
    path('pruebas/', views.list_pruebas, name='list_pruebas'),
    path('pruebas/<int:id_pru>/detalle/', views.detalle_prueba, name='detalle_prueba'),
    path('pruebas/agregar/', views.add_prueba, name='add_prueba'),
    path('ajax/parametros-rubrica/', views.ajax_parametros_rubrica, name='ajax_parametros_rubrica'),
    path('pruebas/<int:id_pru>/editar/', views.edit_prueba, name='edit_prueba'),
    path('pruebas/<int:id_pru>/eliminar/', views.delete_prueba, name='delete_prueba'),

    #------------------------------------------CRUD NOTAS EQUIPO ---------------------------
    path('promedios-guardados-equipo/', views.promedios_jugadores_equipo, name='promedios_guardados_equipo'),

    #------------------------------------------CRUD CICLOS ---------------------------
    path('ciclos/', views.list_ciclo, name='list_ciclo'),
    path('ciclos/add/', views.add_ciclo, name='add_ciclo'),
    path('ciclos/edit/<int:pk>/', views.edit_ciclo, name='edit_ciclo'),
    path('ciclos/delete/<int:pk>/', views.delete_ciclo, name='delete_ciclo'),



    #------------------------------------------DASHBOARD ---------------------------
    path('dashboard/admin/', views.dashboard_admin, name='dashboard_admin'),
    path('dashboard/entrenador/', views.dashboard_entrenador, name='dashboard_entrenador'),
    path('dashboard/jugador/', views.dashboard_jugador, name='dashboard_jugador'),















    #--------------------------------------------------------------------------------------------------

   

]