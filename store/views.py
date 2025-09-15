from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.db import transaction
from django.core.exceptions import PermissionDenied
from django.views.decorators.http import require_http_methods
from .models import Product, Category, Customer, Order, OrderItem
from .forms import (ProductForm, CategoryForm, LoginForm, RegistrationForm, 
                   OrderForm, OrderItemForm, ProfileUpdateForm)
from .forms import (ProductForm, CategoryForm, LoginForm, RegistrationForm, 
                   OrderForm, OrderItemForm, ProfileUpdateForm, CheckoutForm)
from django.conf import settings
from .decorators import ip_rate_limit, user_rate_limit
import time
import logging

# Configurar logging
logger = logging.getLogger(__name__)

# Decorador personalizado para verificar permisos de admin
def admin_required(view_func):
    """Decorador personalizado que requiere permisos de admin"""
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated or not request.user.is_staff:
            logger.warning(f"Acceso no autorizado al admin desde IP: {request.META.get('REMOTE_ADDR')}")
            raise PermissionDenied("Access denied")
        return view_func(request, *args, **kwargs)
    return _wrapped_view

# Función para verificar si un usuario es administrador
def is_admin(user):
    """Verifica permisos de administrador."""
    return user.is_staff

# =============================================================================
# VISTAS DE AUTENTICACIÓN
# =============================================================================

@ip_rate_limit('5/m', method='POST')  # Máximo 5 intentos de login por minuto por IP
@require_http_methods(["GET", "POST"])
def login_view(request):
    """Procesa inicio de sesión y redirecciona según tipo de usuario."""
    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                logger.info(f"Usuario {username} inició sesión exitosamente desde IP: {request.META.get('REMOTE_ADDR')}")
                # Redirigir al dashboard si es admin, a la tienda si es cliente
                if user.is_staff:
                    return redirect('dashboard')
                else:
                    return redirect('store')
            else:
                logger.warning(f"Intento de login fallido para usuario: {username} desde IP: {request.META.get('REMOTE_ADDR')}")
        else:
            logger.warning(f"Formulario de login inválido desde IP: {request.META.get('REMOTE_ADDR')}")
    else:
        form = LoginForm()
    return render(request, 'store/login.html', {'form': form})

@ip_rate_limit('3/h', method='POST')  # Máximo 3 registros por hora por IP
@require_http_methods(["GET", "POST"])
def register_view(request):
    """Procesa registro de nuevos usuarios."""
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            # Por defecto, los usuarios registrados son clientes, no staff
            user.is_staff = False
            user.save()
            logger.info(f"Usuario {user.username} se registró exitosamente desde IP: {request.META.get('REMOTE_ADDR')}")
            login(request, user)
            return redirect('store')
        else:
            logger.warning(f"Registro fallido desde IP: {request.META.get('REMOTE_ADDR')}")
    else:
        form = RegistrationForm()
    return render(request, 'store/register.html', {'form': form})

def logout_view(request):
    """Cierra sesión y redirecciona a login."""
    username = request.user.username if request.user.is_authenticated else 'Anonymous'
    logout(request)
    logger.info(f"Usuario {username} cerró sesión")
    return redirect('login')

# =============================================================================
# VISTAS PRINCIPALES DE LA TIENDA
# =============================================================================

def store(request):
    """Muestra productos y categorías disponibles."""
    products = Product.objects.filter(is_available=True)
    categories = Category.objects.all()
    context = {'products': products, 'categories': categories}
    return render(request, 'store/store.html', context)

def customer_product_detail(request, pk):
    """Muestra detalle de producto y productos relacionados con manejo robusto de errores."""
    try:
        # DEBUG: Log de entrada
        logger.info(f"customer_product_detail llamado con pk={pk}")
        
        # Verificar que pk es un número válido
        try:
            pk = int(pk)
            logger.info(f"pk convertido a entero: {pk}")
        except (ValueError, TypeError):
            logger.error(f"pk inválido: {pk} no es un número")
            raise Http404("Invalid product ID")
        
        # Intentar obtener el producto
        logger.info(f"Buscando producto con pk={pk}")
        product = get_object_or_404(Product, pk=pk)
        logger.info(f"Producto encontrado: {product.name} (ID: {pk})")
        
        # Obtener productos relacionados de forma segura
        try:
            related_products = Product.objects.filter(
                category=product.category,
                is_available=True
            ).exclude(pk=pk)[:4]
            logger.info(f"Productos relacionados encontrados: {related_products.count()}")
        except Exception as e:
            logger.error(f"Error obteniendo productos relacionados: {str(e)}")
            related_products = []
        
        context = {
            'product': product,
            'related_products': related_products
        }
        
        logger.info(f"Renderizando template para producto {pk}")
        return render(request, 'store/customer_product_detail.html', context)
        
    except Http404:
        # Re-lanzar Http404 para manejo correcto
        logger.warning(f"Producto con pk={pk} no encontrado - Http404")
        raise
    except Exception as e:
        # Log del error específico
        logger.error(f"Error inesperado en customer_product_detail para pk={pk}: {str(e)}")
        
        # En desarrollo, mostrar error detallado
        if getattr(settings, 'DEBUG', False):
            raise e
        
        # En producción, mostrar página 404 personalizada
        from django.http import Http404
        raise Http404(f"Product with ID {pk} not found")

logger = logging.getLogger(__name__)

def customer_category_detail(request, pk):
    """Muestra categoría y sus productos disponibles con manejo robusto de errores."""
    try:
        # Validar que pk sea un número válido
        try:
            pk = int(pk)
        except (ValueError, TypeError):
            logger.warning(f"ID de categoría inválido: {pk} desde IP: {request.META.get('REMOTE_ADDR')}")
            raise Http404("Invalid category ID")
        
        # Log para debugging
        logger.info(f"Buscando categoría con ID: {pk}")
        
        # Intentar obtener la categoría
        category = get_object_or_404(Category, pk=pk)
        
        # Obtener productos de la categoría
        products = category.products.filter(is_available=True)
        
        logger.info(f"Categoría encontrada: {category.name} con {products.count()} productos")
        
        context = {
            'category': category,
            'products': products
        }
        return render(request, 'store/customer_category_detail.html', context)
        
    except Http404:
        # Log específico para 404
        logger.warning(f"Categoría con ID {pk} no encontrada - Http404 desde IP: {request.META.get('REMOTE_ADDR')}")
        # Re-lanzar para que Django maneje el 404
        raise
    except Exception as e:
        # Log para otros errores
        logger.error(f"Error inesperado en customer_category_detail para pk={pk}: {str(e)}")
        
        # En desarrollo, mostrar error detallado
        if getattr(settings, 'DEBUG', False):
            raise e
        
        # En producción, mostrar 404
        raise Http404(f"Category with ID {pk} not found")

# =============================================================================
# VISTAS DEL CARRITO
# =============================================================================

@login_required
@user_rate_limit('10/m', method='GET')  # Máximo 10 adiciones al carrito por minuto por usuario
def add_to_cart(request, product_id):
    """Añade producto al carrito o incrementa cantidad."""
    product = get_object_or_404(Product, id=product_id)
    
    # Verificar si hay suficiente stock
    if product.stock <= 0 or not product.is_available:
        messages.warning(request, f"Sorry, {product.name} is out of stock.")
        logger.info(f"Usuario {request.user.username} intentó añadir producto sin stock: {product.name}")
        # Redireccionar a la página anterior si existe
        if request.META.get('HTTP_REFERER'):
            return redirect(request.META.get('HTTP_REFERER'))
        return redirect('store')
    
    # Obtener o crear un pedido en estado pendiente para el usuario
    customer = request.user.customer
    order, created = Order.objects.get_or_create(
        customer=customer, 
        complete=False,
        defaults={'status': 'pending'}
    )
    
    # Buscar si el producto ya está en el carrito
    order_item, created = OrderItem.objects.get_or_create(
        order=order,
        product=product,
        defaults={'quantity': 1}
    )
    
    # Si el producto ya estaba en el carrito, aumentar la cantidad
    if not created:
        # Verificar que no exceda el stock disponible
        if order_item.quantity < product.stock:
            order_item.quantity += 1
            order_item.save()
            messages.success(request, f"{product.name} added to your cart.")
            logger.info(f"Usuario {request.user.username} añadió {product.name} al carrito")
        else:
            messages.warning(request, f"Sorry, we only have {product.stock} units of {product.name} available.")
            logger.warning(f"Usuario {request.user.username} intentó exceder stock disponible para {product.name}")
    else:
        messages.success(request, f"{product.name} added to your cart.")
        logger.info(f"Usuario {request.user.username} añadió nuevo producto {product.name} al carrito")
    
    # Redireccionar a la página anterior si existe
    if request.META.get('HTTP_REFERER'):
        return redirect(request.META.get('HTTP_REFERER'))
    
    return redirect('customer_product_detail', pk=product_id)

@login_required
@user_rate_limit('20/m', method='GET')  # Máximo 20 actualizaciones del carrito por minuto
def update_cart(request, product_id, action):
    """Actualiza cantidad de producto en carrito."""
    product = get_object_or_404(Product, id=product_id)
    customer = request.user.customer
    order = Order.objects.filter(customer=customer, complete=False).first()
    
    if order:
        order_item = OrderItem.objects.filter(order=order, product=product).first()
        
        if order_item:
            if action == 'increase':
                # Verificar que no exceda el stock disponible
                if order_item.quantity < product.stock:
                    order_item.quantity += 1
                    order_item.save()
                    messages.success(request, "Cart updated successfully.")
                    logger.info(f"Usuario {request.user.username} aumentó cantidad de {product.name}")
                else:
                    messages.warning(request, f"Sorry, we only have {product.stock} units of {product.name} available.")
                    logger.warning(f"Usuario {request.user.username} intentó exceder stock para {product.name}")
            elif action == 'decrease':
                if order_item.quantity > 1:
                    order_item.quantity -= 1
                    order_item.save()
                    messages.success(request, "Cart updated successfully.")
                    logger.info(f"Usuario {request.user.username} disminuyó cantidad de {product.name}")
                else:
                    order_item.delete()
                    messages.success(request, f"{product.name} removed from your cart.")
                    logger.info(f"Usuario {request.user.username} eliminó {product.name} del carrito")
                    return redirect('cart')
    
    return redirect('cart')

@login_required
def remove_from_cart(request, product_id):
    """Elimina producto del carrito."""
    product = get_object_or_404(Product, id=product_id)
    customer = request.user.customer
    order = Order.objects.filter(customer=customer, complete=False).first()
    
    if order:
        OrderItem.objects.filter(order=order, product=product).delete()
        messages.success(request, f"{product.name} removed from your cart.")
        logger.info(f"Usuario {request.user.username} eliminó {product.name} del carrito")
    
    return redirect('cart')

@login_required
def cart(request):
    """Muestra carrito de compras actual."""
    customer = request.user.customer
    order = Order.objects.filter(customer=customer, complete=False).first()
    
    if order:
        cart_items = order.orderitem_set.all()
        cart_total = order.get_cart_total
    else:
        cart_items = []
        cart_total = 0
    
    context = {
        'cart_items': cart_items,
        'cart_total': cart_total
    }
    return render(request, 'store/cart.html', context)

# ACTUALIZA la función checkout en store/views.py con esta versión final:

@login_required
@user_rate_limit('2/m', method='POST')
def checkout(request):
    """Procesa página de pago con validaciones estrictas de seguridad y notificaciones mejoradas."""
    customer = request.user.customer
    order = Order.objects.filter(customer=customer, complete=False).first()
    
    if request.method == 'POST':
        form = CheckoutForm(request.POST)
        
        if form.is_valid():
            validated_data = form.cleaned_data
            
            if order:
                try:
                    with transaction.atomic():
                        # Verificar inventario
                        inventory_issue = False
                        order_items = OrderItem.objects.select_related('product').filter(order=order)
                        
                        if not order_items.exists():
                            messages.error(request, "Your cart is empty.")
                            return redirect('cart')
                        
                        for item in order_items:
                            product = Product.objects.get(id=item.product.id)
                            if item.quantity > product.stock or not product.is_available:
                                inventory_issue = True
                                messages.warning(request, f"Sorry, {product.name} is no longer available in the quantity you requested. Available: {product.stock}")
                        
                        if inventory_issue:
                            return redirect('cart')
                        
                        # Actualizar inventario
                        for item in order_items:
                            product = Product.objects.get(id=item.product.id)
                            old_stock = product.stock
                            product.stock = max(0, product.stock - item.quantity)
                            
                            if product.stock <= 0:
                                product.is_available = False
                            
                            product.save()
                            logger.info(f"Producto: {product.name}, Stock anterior: {old_stock}, Stock nuevo: {product.stock}")
                        
                        # Crear dirección de envío con datos sanitizados
                        shipping_info = (
                            f"Name: {validated_data['first_name']} {validated_data['last_name']}\n"
                            f"Email: {validated_data['email']}\n"
                            f"Phone: {validated_data['phone']}\n"
                            f"Address: {validated_data['shipping_address']}"
                        )
                        
                        # Completar el pedido
                        order.complete = True
                        order.status = 'processing'
                        order.transaction_id = f"TX-{int(time.time())}"
                        order.shipping_address = shipping_info
                        order.save()
                        
                        logger.info(f"Orden #{order.id} completada exitosamente para usuario {request.user.username}")
                        
                        # Mensaje de éxito mejorado con emoji
                        messages.success(request, f"🎉 Order #{order.id} placed successfully! Thank you for your purchase. You will receive a confirmation email shortly.")
                        return redirect('store')
                        
                except Exception as e:
                    logger.error(f"Error en checkout para usuario {request.user.username}: {str(e)}")
                    messages.error(request, "⚠️ There was an error processing your order. Please try again or contact support if the problem persists.")
                    return redirect('cart')
            else:
                messages.error(request, "Your cart is empty. Please add some products before checkout.")
                return redirect('cart')
        else:
            # Los errores se manejan en el template con JavaScript
            logger.warning(f"Formulario de checkout inválido para usuario {request.user.username}: {form.errors}")
    else:
        # Para GET, crear formulario con datos del usuario si están disponibles
        initial_data = {}
        if hasattr(request.user, 'customer'):
            initial_data = {
                'first_name': request.user.first_name,
                'last_name': request.user.last_name,
                'email': request.user.email,
                'phone': request.user.customer.phone if request.user.customer.phone else '',
            }
        form = CheckoutForm(initial=initial_data)
    
    # Preparar datos para mostrar
    if order:
        cart_items = order.orderitem_set.all()
        cart_total = order.get_cart_total
    else:
        cart_items = []
        cart_total = 0
    
    context = {
        'form': form,
        'cart_items': cart_items,
        'cart_total': cart_total
    }
    return render(request, 'store/checkout.html', context)

# =============================================================================
# DASHBOARD ADMINISTRATIVO
# =============================================================================

@admin_required
def dashboard(request):
    """Dashboard administrativo con estadísticas."""
    # Contadores para las tarjetas de estadísticas
    product_count = Product.objects.count()
    category_count = Category.objects.count()
    order_count = Order.objects.count()
    
    # Datos para las tablas de resumen
    products = Product.objects.all().order_by('-created_at')
    orders = Order.objects.all().order_by('-date_ordered')
    
    context = {
        'product_count': product_count,
        'category_count': category_count,
        'order_count': order_count,
        'products': products,
        'orders': orders
    }
    return render(request, 'store/dashboard/dashboard.html', context)

@admin_required
def user_list(request):
    """Lista todos los usuarios registrados."""
    users = User.objects.all().order_by('-date_joined')
    return render(request, 'store/dashboard/user_list.html', {'users': users})

# =============================================================================
# CRUD DE PRODUCTOS
# =============================================================================

@admin_required
def product_list(request):
    """Lista productos para administración."""
    products = Product.objects.all()
    return render(request, 'store/dashboard/product_list.html', {'products': products})

@admin_required
def product_detail(request, pk):
    """Detalle de producto para administración."""
    product = get_object_or_404(Product, pk=pk)
    return render(request, 'store/dashboard/product_detail.html', {'product': product})

@admin_required
def product_create(request):
    """Crea nuevo producto."""
    if request.method == 'POST':
        form = ProductForm(request.POST, request.FILES)
        if form.is_valid():
            product = form.save()
            messages.success(request, f'Product "{product.name}" created successfully!')
            logger.info(f"Admin {request.user.username} creó producto: {product.name}")
            return redirect('product_detail', pk=product.pk)
        else:
            logger.warning(f"Error al crear producto por admin {request.user.username}")
    else:
        form = ProductForm()
    
    return render(request, 'store/dashboard/product_form.html', {
        'form': form,
        'title': 'New Coffee Product'
    })

@admin_required
def product_update(request, pk):
    """Actualiza producto existente."""
    product = get_object_or_404(Product, pk=pk)
    
    if request.method == 'POST':
        form = ProductForm(request.POST, request.FILES, instance=product)
        if form.is_valid():
            product = form.save()
            # Asegurarnos de que si hay stock disponible, el producto esté marcado como disponible
            if product.stock > 0 and not product.is_available:
                product.is_available = True
                product.save()
            messages.success(request, f'Product "{product.name}" updated successfully!')
            logger.info(f"Admin {request.user.username} actualizó producto: {product.name}")
            return redirect('product_detail', pk=product.pk)
        else:
            logger.warning(f"Error al actualizar producto {product.name} por admin {request.user.username}")
    else:
        form = ProductForm(instance=product)
    
    return render(request, 'store/dashboard/product_form.html', {
        'form': form,
        'product': product,
        'title': f'Edit {product.name}'
    })

@admin_required
def product_delete(request, pk):
    """Elimina producto con confirmación."""
    product = get_object_or_404(Product, pk=pk)
    
    if request.method == 'POST':
        product_name = product.name
        product.delete()
        messages.success(request, f'Product "{product_name}" deleted successfully!')
        logger.info(f"Admin {request.user.username} eliminó producto: {product_name}")
        return redirect('product_list')
    
    return render(request, 'store/dashboard/product_confirm_delete.html', {'product': product})

# =============================================================================
# CRUD DE CATEGORÍAS
# =============================================================================

@admin_required
def category_list(request):
    """Lista categorías para administración."""
    categories = Category.objects.all()
    return render(request, 'store/dashboard/category_list.html', {'categories': categories})

@admin_required
def category_detail(request, pk):
    """Detalle de categoría y sus productos."""
    category = get_object_or_404(Category, pk=pk)
    products = category.products.all()
    return render(request, 'store/dashboard/category_detail.html', {
        'category': category,
        'products': products
    })

@admin_required
def category_create(request):
    """Crea nueva categoría."""
    if request.method == 'POST':
        form = CategoryForm(request.POST)
        if form.is_valid():
            category = form.save()
            messages.success(request, f'Category "{category.name}" created successfully!')
            logger.info(f"Admin {request.user.username} creó categoría: {category.name}")
            return redirect('category_detail', pk=category.pk)
        else:
            logger.warning(f"Error al crear categoría por admin {request.user.username}")
    else:
        form = CategoryForm()
    
    return render(request, 'store/dashboard/category_form.html', {
        'form': form,
        'title': 'New Category'
    })

@admin_required
def category_update(request, pk):
    """Actualiza categoría existente."""
    category = get_object_or_404(Category, pk=pk)
    
    if request.method == 'POST':
        form = CategoryForm(request.POST, instance=category)
        if form.is_valid():
            form.save()
            messages.success(request, f'Category "{category.name}" updated successfully!')
            logger.info(f"Admin {request.user.username} actualizó categoría: {category.name}")
            return redirect('category_detail', pk=category.pk)
        else:
            logger.warning(f"Error al actualizar categoría {category.name} por admin {request.user.username}")
    else:
        form = CategoryForm(instance=category)
    
    return render(request, 'store/dashboard/category_form.html', {
        'form': form,
        'category': category,
        'title': f'Edit {category.name}'
    })

@admin_required
def category_delete(request, pk):
    """Elimina categoría con confirmación."""
    category = get_object_or_404(Category, pk=pk)
    
    if request.method == 'POST':
        category_name = category.name
        category.delete()
        messages.success(request, f'Category "{category_name}" deleted successfully!')
        logger.info(f"Admin {request.user.username} eliminó categoría: {category_name}")
        return redirect('category_list')
    
    return render(request, 'store/dashboard/category_confirm_delete.html', {'category': category})

# =============================================================================
# CRUD DE ÓRDENES
# =============================================================================

@admin_required
def order_list(request):
    """Lista órdenes para administración."""
    orders = Order.objects.all()
    return render(request, 'store/dashboard/order_list.html', {'orders': orders})

@admin_required
def order_detail(request, pk):
    """Detalle de orden y sus productos."""
    order = get_object_or_404(Order, pk=pk)
    return render(request, 'store/dashboard/order_detail.html', {'order': order})

@admin_required
def order_update(request, pk):
    """Actualiza estado y dirección de orden."""
    order = get_object_or_404(Order, pk=pk)
    old_status = order.status
    
    if request.method == 'POST':
        form = OrderForm(request.POST, instance=order)
        if form.is_valid():
            new_status = form.cleaned_data['status']
            
            try:
                # Usar transacción atómica para asegurar consistencia
                with transaction.atomic():
                    # Si el pedido cambia de cancelado a otro estado, verificar disponibilidad
                    if old_status == 'cancelled' and new_status != 'cancelled':
                        order_items = OrderItem.objects.select_related('product').filter(order=order)
                        inventory_issue = False
                        
                        # Verificar disponibilidad de todos los productos
                        for item in order_items:
                            product = Product.objects.get(id=item.product.id)
                            if product.stock < item.quantity:
                                inventory_issue = True
                                messages.warning(request, f"Not enough stock available for {product.name}. Available: {product.stock}")
                        
                        if inventory_issue:
                            logger.warning(f"Admin {request.user.username} no pudo cambiar estado de orden {order.id} por falta de stock")
                            return redirect('order_detail', pk=order.pk)
                        
                        # Si no hay problemas, reducir el inventario
                        for item in order_items:
                            product = Product.objects.get(id=item.product.id)
                            old_stock = product.stock
                            product.stock = max(0, product.stock - item.quantity)
                            if product.stock <= 0:
                                product.stock = 0
                                product.is_available = False
                            product.save()
                            logger.info(f"Orden reactivada: Producto {product.name}, Stock anterior: {old_stock}, Stock nuevo: {product.stock}")
                    
                    # Si el pedido está siendo cancelado, devolver productos al inventario
                    elif old_status != 'cancelled' and new_status == 'cancelled':
                        order_items = OrderItem.objects.select_related('product').filter(order=order)
                        for item in order_items:
                            product = Product.objects.get(id=item.product.id)
                            old_stock = product.stock
                            product.stock += item.quantity
                            product.is_available = True
                            product.save()
                            logger.info(f"Orden cancelada: Producto {product.name}, Stock anterior: {old_stock}, Stock nuevo: {product.stock}")
                    
                    form.save()
                    messages.success(request, f'Order #{order.id} updated successfully!')
                    logger.info(f"Admin {request.user.username} actualizó orden {order.id} de {old_status} a {new_status}")
                    
                    # Si la solicitud es AJAX, devolver respuesta JSON
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return JsonResponse({'status': 'success'})
                    return redirect('order_detail', pk=order.pk)
            
            except Exception as e:
                logger.error(f"Error al actualizar orden {order.id} por admin {request.user.username}: {str(e)}")
                messages.error(request, "There was an error updating the order status. Please try again.")
                return redirect('order_detail', pk=order.pk)
        else:
            logger.warning(f"Formulario inválido al actualizar orden {order.id} por admin {request.user.username}")
    else:
        form = OrderForm(instance=order)
    
    return render(request, 'store/dashboard/order_form.html', {
        'form': form,
        'order': order,
        'title': f'Edit Order #{order.id}'
    })

@admin_required
def order_delete(request, pk):
    """Elimina orden con confirmación."""
    order = get_object_or_404(Order, pk=pk)
    
    if request.method == 'POST':
        try:
            with transaction.atomic():
                # Si se elimina una orden completada, restaurar el inventario
                if order.complete and order.status != 'cancelled':
                    order_items = OrderItem.objects.select_related('product').filter(order=order)
                    for item in order_items:
                        product = Product.objects.get(id=item.product.id)
                        old_stock = product.stock
                        product.stock += item.quantity
                        product.is_available = True
                        product.save()
                        logger.info(f"Orden eliminada: Producto {product.name}, Stock anterior: {old_stock}, Stock nuevo: {product.stock}")
                
                order_id = order.id
                order.delete()
                messages.success(request, f'Order #{order_id} deleted successfully!')
                logger.info(f"Admin {request.user.username} eliminó orden {order_id}")
                return redirect('order_list')
        
        except Exception as e:
            logger.error(f"Error al eliminar orden {order.id} por admin {request.user.username}: {str(e)}")
            messages.error(request, "There was an error deleting the order. Please try again.")
            return redirect('order_detail', pk=order.pk)
    
    return render(request, 'store/dashboard/order_confirm_delete.html', {'order': order})

@admin_required
def add_order_item(request, pk):
    """Añade producto a una orden."""
    order = get_object_or_404(Order, pk=pk)
    
    if request.method == 'POST':
        form = OrderItemForm(request.POST)
        if form.is_valid():
            product = form.cleaned_data['product']
            quantity = form.cleaned_data['quantity']
            
            try:
                with transaction.atomic():
                    product = Product.objects.get(id=product.id)
                    
                    # Verificar stock si la orden está completada
                    if product.stock < quantity and order.complete and order.status != 'cancelled':
                        messages.warning(request, f"Not enough stock available for {product.name}. Available: {product.stock}")
                        logger.warning(f"Admin {request.user.username} intentó añadir ítem sin stock a orden {order.id}")
                        return redirect('order_detail', pk=order.pk)
                    
                    item = form.save(commit=False)
                    item.order = order
                    item.save()
                    
                    # Reducir stock si la orden está completada
                    if order.complete and order.status != 'cancelled':
                        old_stock = product.stock
                        product.stock = max(0, product.stock - quantity)
                        if product.stock <= 0:
                            product.stock = 0
                            product.is_available = False
                        product.save()
                        logger.info(f"Ítem añadido a orden completada: Producto {product.name}, Stock anterior: {old_stock}, Stock nuevo: {product.stock}")
                    
                    messages.success(request, 'Item added to the order successfully!')
                    logger.info(f"Admin {request.user.username} añadió ítem {product.name} a orden {order.id}")
                    return redirect('order_detail', pk=order.pk)
            
            except Exception as e:
                logger.error(f"Error al añadir ítem a orden {order.id} por admin {request.user.username}: {str(e)}")
                messages.error(request, "There was an error adding the item to the order. Please try again.")
                return redirect('order_detail', pk=order.pk)
        else:
            logger.warning(f"Formulario inválido al añadir ítem a orden {order.id} por admin {request.user.username}")
    else:
        form = OrderItemForm()
    
    return render(request, 'store/dashboard/order_item_form.html', {
        'form': form,
        'order': order,
        'title': f'Add Item to Order #{order.id}'
    })

@admin_required
def edit_order_item(request, pk):
    """Edita producto de una orden."""
    item = get_object_or_404(OrderItem, pk=pk)
    old_quantity = item.quantity
    order = item.order
    
    if request.method == 'POST':
        form = OrderItemForm(request.POST, instance=item)
        if form.is_valid():
            new_quantity = form.cleaned_data['quantity']
            product_id = form.cleaned_data['product'].id
            
            try:
                with transaction.atomic():
                    product = Product.objects.get(id=product_id)
                    
                    # Si la orden está completada, ajustar inventario
                    if order.complete and order.status != 'cancelled':
                        quantity_difference = new_quantity - old_quantity
                        
                        if quantity_difference > 0 and product.stock < quantity_difference:
                            messages.warning(request, f"Not enough stock available for {product.name}. Available: {product.stock}")
                            logger.warning(f"Admin {request.user.username} intentó editar ítem sin stock suficiente en orden {order.id}")
                            return redirect('order_detail', pk=order.pk)
                        
                        old_stock = product.stock
                        product.stock = max(0, product.stock - quantity_difference)
                        if product.stock <= 0:
                            product.stock = 0
                            product.is_available = False
                        elif product.stock > 0:
                            product.is_available = True
                        product.save()
                        logger.info(f"Ítem editado: Producto {product.name}, Stock anterior: {old_stock}, Stock nuevo: {product.stock}")
                    
                    form.save()
                    messages.success(request, 'Order item updated successfully!')
                    logger.info(f"Admin {request.user.username} editó ítem en orden {order.id}")
                    return redirect('order_detail', pk=item.order.pk)
            
            except Exception as e:
                logger.error(f"Error al editar ítem de orden {order.id} por admin {request.user.username}: {str(e)}")
                messages.error(request, "There was an error updating the order item. Please try again.")
                return redirect('order_detail', pk=order.pk)
        else:
            logger.warning(f"Formulario inválido al editar ítem de orden {order.id} por admin {request.user.username}")
    else:
        form = OrderItemForm(instance=item)
    
    return render(request, 'store/dashboard/order_item_form.html', {
        'form': form,
        'item': item,
        'order': item.order,
        'title': f'Edit Item in Order #{item.order.id}'
    })

@admin_required
def delete_order_item(request, pk):
    """Elimina producto de una orden."""
    item = get_object_or_404(OrderItem, pk=pk)
    order = item.order
    
    if request.method == 'POST':
        try:
            with transaction.atomic():
                # Si la orden está completada, restaurar inventario
                if order.complete and order.status != 'cancelled':
                    product = Product.objects.get(id=item.product.id)
                    old_stock = product.stock
                    product.stock += item.quantity
                    product.is_available = True
                    product.save()
                    logger.info(f"Ítem eliminado: Producto {product.name}, Stock anterior: {old_stock}, Stock nuevo: {product.stock}")
                
                item.delete()
                messages.success(request, 'Order item removed successfully!')
                logger.info(f"Admin {request.user.username} eliminó ítem de orden {order.id}")
                return redirect('order_detail', pk=order.pk)
        
        except Exception as e:
            logger.error(f"Error al eliminar ítem de orden {order.id} por admin {request.user.username}: {str(e)}")
            messages.error(request, "There was an error removing the order item. Please try again.")
            return redirect('order_detail', pk=order.pk)
    
    return render(request, 'store/dashboard/order_item_confirm_delete.html', {
        'item': item,
        'order': order
    })

# =============================================================================
# VISTAS DE CUENTA DE USUARIO
# =============================================================================

@login_required
@user_rate_limit('5/m', method='POST')  # Máximo 5 actualizaciones de perfil por minuto
def my_account(request):
    """Gestiona perfil del usuario con formulario mejorado y validaciones estrictas."""
    customer = request.user.customer
    
    if request.method == 'POST':
        form = ProfileUpdateForm(request.POST, instance=request.user)
        if form.is_valid():
            # Guardar datos del usuario
            user = form.save()
            
            # Actualizar datos del cliente con validaciones
            customer.phone = form.cleaned_data.get('phone', '')
            customer.address = form.cleaned_data.get('address', '')
            customer.save()
            
            messages.success(request, "Your account information has been updated successfully!")
            logger.info(f"Usuario {request.user.username} actualizó su perfil desde IP: {request.META.get('REMOTE_ADDR')}")
            logger.info(f"Nuevos datos - Teléfono: {customer.phone}, Dirección: {customer.address[:50] if customer.address else 'No address'}...")
            return redirect('my_account')
        else:
            logger.warning(f"Error al actualizar perfil de usuario {request.user.username} desde IP: {request.META.get('REMOTE_ADDR')}")
            logger.warning(f"Errores del formulario: {form.errors}")
            # Mostrar errores específicos al usuario
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field.title()}: {error}")
    else:
        # Precargar el formulario con datos existentes
        initial_data = {
            'phone': customer.phone,
            'address': customer.address
        }
        form = ProfileUpdateForm(instance=request.user, initial=initial_data)
    
    context = {
        'form': form,
        'user': request.user,
        'customer': customer
    }
    return render(request, 'store/my_account.html', context)

@login_required
def my_orders(request):
    """Lista pedidos del usuario."""
    customer = request.user.customer
    orders = Order.objects.filter(customer=customer).order_by('-date_ordered')
    
    context = {
        'orders': orders
    }
    return render(request, 'store/my_orders.html', context)

@login_required
def order_customer_detail(request, pk):
    """Detalle de pedido específico del cliente."""
    customer = request.user.customer
    order = get_object_or_404(Order, pk=pk, customer=customer)  # Asegurar que el pedido pertenece al cliente
    context = {
        'order': order
    }
    return render(request, 'store/order_customer_detail.html', context)

