# store/views.py - ARCHIVO COMPLETO CON MEJORAS DE SEGURIDAD
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.http import JsonResponse, HttpResponseForbidden
from django.db import transaction
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods, require_POST
from django.core.exceptions import ValidationError, PermissionDenied
from django.utils.html import strip_tags
from django.db.models import Q
from .models import Product, Category, Customer, Order, OrderItem
from .forms import (ProductForm, CategoryForm, LoginForm, RegistrationForm, 
                   OrderForm, OrderItemForm)
import time
import logging
from datetime import datetime, timedelta

# Configurar logging
logger = logging.getLogger(__name__)
security_logger = logging.getLogger('security')

# Diccionario para tracking de intentos de login (en producción usar Redis/Cache)
login_attempts = {}

# Funciones de utilidad de seguridad
def get_client_ip(request):
    """Obtiene la IP del cliente de forma segura"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', '')
    return ip

def log_security_event(event_type, user, ip_address, details=""):
    """Registra eventos de seguridad"""
    security_logger.info(f"Security Event: {event_type} | User: {user} | IP: {ip_address} | Details: {details}")

def validate_text_input(value, field_name="input", max_length=500):
    """Validación básica de entrada de texto"""
    if not value:
        return ""
    
    value = str(value).strip()
    
    # Verificar longitud
    if len(value) > max_length:
        raise ValidationError(f"{field_name} must be less than {max_length} characters")
    
    # Patrones básicos de inyección SQL
    sql_patterns = [
        "union select", "drop table", "insert into", "update set",
        "delete from", "exec(", "script>", "javascript:", "--", "/*"
    ]
    
    value_lower = value.lower()
    for pattern in sql_patterns:
        if pattern in value_lower:
            logger.warning(f"Suspicious input detected in {field_name}: {value}")
            raise ValidationError(f"Invalid characters detected in {field_name}")
    
    # Sanitizar HTML básico
    value = value.replace('<', '&lt;').replace('>', '&gt;')
    value = value.replace('"', '&quot;').replace("'", '&#x27;')
    
    return value

def rate_limit_login(func):
    """Decorador para limitar intentos de login"""
    def wrapper(request, *args, **kwargs):
        client_ip = get_client_ip(request)
        current_time = datetime.now()
        
        # Limpiar intentos antiguos (más de 15 minutos)
        if client_ip in login_attempts:
            login_attempts[client_ip] = [
                attempt for attempt in login_attempts[client_ip] 
                if current_time - attempt < timedelta(minutes=15)
            ]
        
        # Verificar límite de intentos (5 intentos máximo)
        if client_ip in login_attempts and len(login_attempts[client_ip]) >= 5:
            security_logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            messages.error(request, "Too many login attempts. Please try again later.")
            return render(request, 'store/login.html', {'form': LoginForm()})
        
        return func(request, *args, **kwargs)
    return wrapper

def is_admin(user):
    """Verifica permisos de administrador"""
    if not user.is_staff:
        security_logger.warning(f"Unauthorized admin access attempt by user: {user.username}")
    return user.is_staff

# VISTAS DE AUTENTICACIÓN
@csrf_protect
@never_cache
@rate_limit_login
@require_http_methods(["GET", "POST"])
def login_view(request):
    """Procesa inicio de sesión con mejoras de seguridad"""
    client_ip = get_client_ip(request)
    
    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            
            try:
                # Validar entrada del usuario
                username = validate_text_input(username, "username", 150)
                
                user = authenticate(username=username, password=password)
                if user is not None:
                    if user.is_active:
                        login(request, user)
                        log_security_event("LOGIN_SUCCESS", user.username, client_ip)
                        
                        # Limpiar intentos fallidos
                        if client_ip in login_attempts:
                            del login_attempts[client_ip]
                        
                        # Redirigir según tipo de usuario
                        if user.is_staff:
                            return redirect('dashboard')
                        else:
                            return redirect('store')
                    else:
                        log_security_event("LOGIN_INACTIVE_USER", username, client_ip)
                        messages.error(request, "Your account has been deactivated.")
                else:
                    # Registrar intento fallido
                    if client_ip not in login_attempts:
                        login_attempts[client_ip] = []
                    login_attempts[client_ip].append(datetime.now())
                    
                    log_security_event("LOGIN_FAILED", username, client_ip)
                    messages.error(request, "Invalid username or password.")
            
            except ValidationError as e:
                log_security_event("LOGIN_INVALID_INPUT", username if 'username' in locals() else "unknown", client_ip)
                messages.error(request, "Invalid input detected.")
        else:
            log_security_event("LOGIN_FORM_INVALID", "unknown", client_ip)
    else:
        form = LoginForm()
    
    return render(request, 'store/login.html', {'form': form})

@csrf_protect
@require_http_methods(["GET", "POST"])
def register_view(request):
    """Procesa registro seguro de nuevos usuarios"""
    client_ip = get_client_ip(request)
    
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            try:
                with transaction.atomic():
                    user = form.save()
                    user.is_staff = False
                    user.save()
                    
                    log_security_event("USER_REGISTERED", user.username, client_ip)
                    login(request, user)
                    messages.success(request, "Account created successfully!")
                    return redirect('store')
            
            except Exception as e:
                log_security_event("REGISTRATION_ERROR", "unknown", client_ip, str(e))
                messages.error(request, "There was an error creating your account. Please try again.")
        else:
            log_security_event("REGISTRATION_INVALID", "unknown", client_ip)
    else:
        form = RegistrationForm()
    
    return render(request, 'store/register.html', {'form': form})

@never_cache
def logout_view(request):
    """Cierra sesión segura"""
    if request.user.is_authenticated:
        log_security_event("LOGOUT", request.user.username, get_client_ip(request))
        logout(request)
    return redirect('login')

# VISTAS PRINCIPALES DE LA TIENDA
@require_http_methods(["GET"])
def store(request):
    """Muestra productos y categorías disponibles con búsqueda segura"""
    try:
        # Procesar búsqueda si existe
        search_query = request.GET.get('search', '').strip()
        products = Product.objects.filter(is_available=True)
        
        if search_query:
            try:
                # Validar query de búsqueda
                search_query = validate_text_input(search_query, "search query", 100)
                log_security_event("SEARCH_QUERY", 
                                 request.user.username if request.user.is_authenticated else "anonymous", 
                                 get_client_ip(request), search_query)
                
                # Búsqueda segura usando Q objects
                products = products.filter(
                    Q(name__icontains=search_query) | 
                    Q(description__icontains=search_query) |
                    Q(origin__icontains=search_query)
                )
            except ValidationError:
                messages.warning(request, "Invalid search query.")
                search_query = ""
        
        categories = Category.objects.all()
        context = {
            'products': products, 
            'categories': categories,
            'search_query': search_query
        }
        return render(request, 'store/store.html', context)
    
    except Exception as e:
        logger.error(f"Error in store view: {str(e)}")
        messages.error(request, "An error occurred while loading the store.")
        return render(request, 'store/store.html', {
            'products': [], 
            'categories': [],
            'search_query': ""
        })

@require_http_methods(["GET"])
def customer_product_detail(request, pk):
    """Muestra detalle de producto con validación de parámetros"""
    try:
        # Validar que pk sea un entero válido
        if not isinstance(pk, int) or pk <= 0:
            raise ValidationError("Invalid product ID")
        
        product = get_object_or_404(Product, pk=pk)
        related_products = Product.objects.filter(
            category=product.category,
            is_available=True
        ).exclude(pk=pk)[:4]
        
        context = {
            'product': product,
            'related_products': related_products
        }
        return render(request, 'store/customer_product_detail.html', context)
    
    except Exception as e:
        logger.error(f"Error in product detail view: {str(e)}")
        messages.error(request, "Product not found.")
        return redirect('store')

@require_http_methods(["GET"])
def customer_category_detail(request, pk):
    """Muestra categoría y sus productos disponibles"""
    try:
        if not isinstance(pk, int) or pk <= 0:
            raise ValidationError("Invalid category ID")
            
        category = get_object_or_404(Category, pk=pk)
        products = category.products.filter(is_available=True)
        context = {
            'category': category,
            'products': products
        }
        return render(request, 'store/customer_category_detail.html', context)
    
    except Exception as e:
        logger.error(f"Error in category detail view: {str(e)}")
        messages.error(request, "Category not found.")
        return redirect('store')

# VISTAS DEL CARRITO
@login_required
@csrf_protect
@require_POST
def add_to_cart(request, product_id):
    """Añade producto al carrito con validaciones de seguridad"""
    try:
        # Validar product_id
        if not isinstance(product_id, int) or product_id <= 0:
            raise ValidationError("Invalid product ID")
        
        product = get_object_or_404(Product, id=product_id)
        
        # Verificaciones de seguridad
        if not product.is_available or product.stock <= 0:
            log_security_event("CART_ADD_UNAVAILABLE_PRODUCT", 
                             request.user.username, get_client_ip(request), 
                             f"Product: {product.name}")
            messages.warning(request, f"Sorry, {product.name} is out of stock.")
            return redirect(request.META.get('HTTP_REFERER', 'store'))
        
        with transaction.atomic():
            customer = request.user.customer
            order, created = Order.objects.get_or_create(
                customer=customer, 
                complete=False,
                defaults={'status': 'pending'}
            )
            
            order_item, item_created = OrderItem.objects.get_or_create(
                order=order,
                product=product,
                defaults={'quantity': 1}
            )
            
            if not item_created:
                if order_item.quantity < product.stock:
                    order_item.quantity += 1
                    order_item.save()
                    log_security_event("CART_ITEM_ADDED", request.user.username, 
                                     get_client_ip(request), f"Product: {product.name}")
                    messages.success(request, f"{product.name} added to your cart.")
                else:
                    log_security_event("CART_ADD_EXCEED_STOCK", request.user.username, 
                                     get_client_ip(request), f"Product: {product.name}")
                    messages.warning(request, f"Sorry, we only have {product.stock} units available.")
            else:
                log_security_event("CART_ITEM_ADDED", request.user.username, 
                                 get_client_ip(request), f"Product: {product.name}")
                messages.success(request, f"{product.name} added to your cart.")
        
        return redirect(request.META.get('HTTP_REFERER', 'store'))
    
    except Exception as e:
        logger.error(f"Error adding to cart: {str(e)}")
        log_security_event("CART_ADD_ERROR", request.user.username, 
                         get_client_ip(request), str(e))
        messages.error(request, "Error adding product to cart.")
        return redirect('store')

@login_required
@csrf_protect
@require_POST
def update_cart(request, product_id, action):
    """Actualiza cantidad con validaciones estrictas"""
    try:
        # Validar parámetros
        if not isinstance(product_id, int) or product_id <= 0:
            raise ValidationError("Invalid product ID")
        
        if action not in ['increase', 'decrease']:
            raise ValidationError("Invalid action")
        
        product = get_object_or_404(Product, id=product_id)
        customer = request.user.customer
        order = Order.objects.filter(customer=customer, complete=False).first()
        
        if not order:
            messages.warning(request, "No active cart found.")
            return redirect('cart')
        
        order_item = OrderItem.objects.filter(order=order, product=product).first()
        
        if not order_item:
            messages.warning(request, "Product not in cart.")
            return redirect('cart')
        
        with transaction.atomic():
            if action == 'increase':
                if order_item.quantity < product.stock:
                    order_item.quantity += 1
                    order_item.save()
                    log_security_event("CART_ITEM_INCREASED", request.user.username, 
                                     get_client_ip(request), f"Product: {product.name}")
                    messages.success(request, "Cart updated successfully.")
                else:
                    log_security_event("CART_INCREASE_EXCEED_STOCK", request.user.username, 
                                     get_client_ip(request), f"Product: {product.name}")
                    messages.warning(request, f"Cannot exceed available stock ({product.stock} units).")
            
            elif action == 'decrease':
                if order_item.quantity > 1:
                    order_item.quantity -= 1
                    order_item.save()
                    log_security_event("CART_ITEM_DECREASED", request.user.username, 
                                     get_client_ip(request), f"Product: {product.name}")
                    messages.success(request, "Cart updated successfully.")
                else:
                    order_item.delete()
                    log_security_event("CART_ITEM_REMOVED", request.user.username, 
                                     get_client_ip(request), f"Product: {product.name}")
                    messages.success(request, f"{product.name} removed from cart.")
        
        return redirect('cart')
    
    except Exception as e:
        logger.error(f"Error updating cart: {str(e)}")
        log_security_event("CART_UPDATE_ERROR", request.user.username, 
                         get_client_ip(request), str(e))
        messages.error(request, "Error updating cart.")
        return redirect('cart')

@login_required
@csrf_protect
@require_POST
def remove_from_cart(request, product_id):
    """Elimina producto del carrito"""
    try:
        if not isinstance(product_id, int) or product_id <= 0:
            raise ValidationError("Invalid product ID")
            
        product = get_object_or_404(Product, id=product_id)
        customer = request.user.customer
        order = Order.objects.filter(customer=customer, complete=False).first()
        
        if order:
            OrderItem.objects.filter(order=order, product=product).delete()
            log_security_event("CART_ITEM_REMOVED", request.user.username, 
                             get_client_ip(request), f"Product: {product.name}")
            messages.success(request, f"{product.name} removed from your cart.")
        
        return redirect('cart')
    
    except Exception as e:
        logger.error(f"Error removing from cart: {str(e)}")
        messages.error(request, "Error removing product from cart.")
        return redirect('cart')

@login_required
def cart(request):
    """Muestra carrito de compras actual"""
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

@login_required
@csrf_protect
def checkout(request):
    """Procesa checkout con validaciones completas de seguridad"""
    customer = request.user.customer
    order = Order.objects.filter(customer=customer, complete=False).first()
    
    if request.method == 'POST':
        if not order or not order.orderitem_set.exists():
            log_security_event("CHECKOUT_EMPTY_CART", request.user.username, 
                             get_client_ip(request))
            messages.error(request, "Your cart is empty.")
            return redirect('cart')
        
        try:
            # Validar dirección de envío
            shipping_address = request.POST.get('shipping_address', '').strip()
            if not shipping_address:
                messages.error(request, "Shipping address is required.")
                return redirect('checkout')
            
            # Validar dirección con nuestro validador
            try:
                shipping_address = validate_text_input(shipping_address, "shipping address", 500)
                if len(shipping_address.strip()) < 10:
                    raise ValidationError("Address too short")
            except ValidationError as e:
                messages.error(request, f"Invalid shipping address: {str(e)}")
                return redirect('checkout')
            
            with transaction.atomic():
                # Verificar inventario y disponibilidad
                order_items = OrderItem.objects.select_related('product').filter(order=order)
                inventory_issues = []
                
                for item in order_items:
                    product = Product.objects.select_for_update().get(id=item.product.id)
                    if item.quantity > product.stock or not product.is_available:
                        inventory_issues.append({
                            'product': product.name,
                            'requested': item.quantity,
                            'available': product.stock
                        })
                
                if inventory_issues:
                    for issue in inventory_issues:
                        messages.warning(request, 
                                       f"{issue['product']}: Requested {issue['requested']}, "
                                       f"but only {issue['available']} available")
                    log_security_event("CHECKOUT_INVENTORY_ISSUE", request.user.username, 
                                     get_client_ip(request), str(inventory_issues))
                    return redirect('cart')
                
                # Actualizar inventario
                for item in order_items:
                    product = Product.objects.get(id=item.product.id)
                    old_stock = product.stock
                    product.stock = max(0, product.stock - item.quantity)
                    
                    if product.stock <= 0:
                        product.is_available = False
                    
                    product.save()
                    logger.info(f"Inventory updated - {product.name}: {old_stock} -> {product.stock}")
                
                # Completar orden
                order.complete = True
                order.status = 'processing'
                order.transaction_id = f"TX-{int(time.time())}-{customer.id}"
                order.shipping_address = shipping_address
                order.save()
                
                log_security_event("CHECKOUT_SUCCESS", request.user.username, 
                                 get_client_ip(request), f"Order ID: {order.id}")
                messages.success(request, f"Order #{order.id} placed successfully!")
                return redirect('store')
        
        except Exception as e:
            logger.error(f"Checkout error: {str(e)}")
            log_security_event("CHECKOUT_ERROR", request.user.username, 
                             get_client_ip(request), str(e))
            messages.error(request, "Error processing your order. Please try again.")
            return redirect('cart')
    
    # GET request
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
    return render(request, 'store/checkout.html', context)

# VISTAS ADMINISTRATIVAS
@user_passes_test(is_admin)
@require_http_methods(["GET"])
def dashboard(request):
    """Dashboard administrativo seguro"""
    try:
        log_security_event("ADMIN_DASHBOARD_ACCESS", request.user.username, 
                         get_client_ip(request))
        
        # Estadísticas básicas
        product_count = Product.objects.count()
        category_count = Category.objects.count()
        order_count = Order.objects.count()
        
        # Datos recientes
        products = Product.objects.all().order_by('-created_at')[:5]
        orders = Order.objects.all().order_by('-date_ordered')[:5]
        
        context = {
            'product_count': product_count,
            'category_count': category_count,
            'order_count': order_count,
            'products': products,
            'orders': orders
        }
        return render(request, 'store/dashboard/dashboard.html', context)
    
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        messages.error(request, "Error loading dashboard.")
        return render(request, 'store/dashboard/dashboard.html', {
            'product_count': 0,
            'category_count': 0,
            'order_count': 0,
            'products': [],
            'orders': []
        })

@user_passes_test(is_admin)
def user_list(request):
    """Lista todos los usuarios registrados"""
    users = User.objects.all().order_by('-date_joined')
    return render(request, 'store/dashboard/user_list.html', {'users': users})

# CRUD DE PRODUCTOS
@user_passes_test(is_admin)
def product_list(request):
    """Lista productos para administración"""
    products = Product.objects.all()
    return render(request, 'store/dashboard/product_list.html', {'products': products})

@user_passes_test(is_admin)
def product_detail(request, pk):
    """Detalle de producto para administración"""
    product = get_object_or_404(Product, pk=pk)
    return render(request, 'store/dashboard/product_detail.html', {'product': product})

@user_passes_test(is_admin)
@csrf_protect
def product_create(request):
    """Crea nuevo producto con validaciones completas"""
    if request.method == 'POST':
        form = ProductForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                with transaction.atomic():
                    product = form.save()
                    log_security_event("PRODUCT_CREATED", request.user.username, 
                                     get_client_ip(request), f"Product: {product.name}")
                    messages.success(request, f'Product "{product.name}" created successfully!')
                    return redirect('product_detail', pk=product.pk)
            except Exception as e:
                logger.error(f"Product creation error: {str(e)}")
                log_security_event("PRODUCT_CREATE_ERROR", request.user.username, 
                                 get_client_ip(request), str(e))
                messages.error(request, "Error creating product.")
        else:
            log_security_event("PRODUCT_CREATE_INVALID_FORM", request.user.username, 
                             get_client_ip(request))
    else:
        form = ProductForm()
    
    return render(request, 'store/dashboard/product_form.html', {
        'form': form,
        'title': 'New Coffee Product'
    })

@user_passes_test(is_admin)
@csrf_protect
def product_update(request, pk):
    """Actualiza producto existente"""
    product = get_object_or_404(Product, pk=pk)
    
    if request.method == 'POST':
        form = ProductForm(request.POST, request.FILES, instance=product)
        if form.is_valid():
            try:
                with transaction.atomic():
                    product = form.save()
                    # Asegurarnos de que si hay stock disponible, el producto esté marcado como disponible
                    if product.stock > 0 and not product.is_available:
                        product.is_available = True
                        product.save()
                    log_security_event("PRODUCT_UPDATED", request.user.username, 
                                     get_client_ip(request), f"Product: {product.name}")
                    messages.success(request, f'Product "{product.name}" updated successfully!')
                    return redirect('product_detail', pk=product.pk)
            except Exception as e:
                logger.error(f"Product update error: {str(e)}")
                messages.error(request, "Error updating product.")
    else:
        form = ProductForm(instance=product)
    
    return render(request, 'store/dashboard/product_form.html', {
        'form': form,
        'product': product,
        'title': f'Edit {product.name}'
    })

@user_passes_test(is_admin)
@csrf_protect
def product_delete(request, pk):
    """Elimina producto con confirmación"""
    product = get_object_or_404(Product, pk=pk)
    
    if request.method == 'POST':
        try:
            product_name = product.name
            product.delete()
            log_security_event("PRODUCT_DELETED", request.user.username, 
                             get_client_ip(request), f"Product: {product_name}")
            messages.success(request, f'Product "{product_name}" deleted successfully!')
            return redirect('product_list')
        except Exception as e:
            logger.error(f"Product deletion error: {str(e)}")
            messages.error(request, "Error deleting product.")
    
    return render(request, 'store/dashboard/product_confirm_delete.html', {'product': product})

# CRUD DE CATEGORÍAS
@user_passes_test(is_admin)
def category_list(request):
    """Lista categorías para administración"""
    categories = Category.objects.all()
    return render(request, 'store/dashboard/category_list.html', {'categories': categories})

@user_passes_test(is_admin)
def category_detail(request, pk):
    """Detalle de categoría y sus productos"""
    category = get_object_or_404(Category, pk=pk)
    products = category.products.all()
    return render(request, 'store/dashboard/category_detail.html', {
        'category': category,
        'products': products
    })

@user_passes_test(is_admin)
@csrf_protect
def category_create(request):
    """Crea nueva categoría"""
    if request.method == 'POST':
        form = CategoryForm(request.POST)
        if form.is_valid():
            try:
                category = form.save()
                log_security_event("CATEGORY_CREATED", request.user.username, 
                                 get_client_ip(request), f"Category: {category.name}")
                messages.success(request, f'Category "{category.name}" created successfully!')
                return redirect('category_detail', pk=category.pk)
            except Exception as e:
                logger.error(f"Category creation error: {str(e)}")
                messages.error(request, "Error creating category.")
    else:
        form = CategoryForm()
    
    return render(request, 'store/dashboard/category_form.html', {
        'form': form,
        'title': 'New Category'
    })

@user_passes_test(is_admin)
@csrf_protect
def category_update(request, pk):
    """Actualiza categoría existente"""
    category = get_object_or_404(Category, pk=pk)
    
    if request.method == 'POST':
        form = CategoryForm(request.POST, instance=category)
        if form.is_valid():
            try:
                form.save()
                log_security_event("CATEGORY_UPDATED", request.user.username, 
                                 get_client_ip(request), f"Category: {category.name}")
                messages.success(request, f'Category "{category.name}" updated successfully!')
                return redirect('category_detail', pk=category.pk)
            except Exception as e:
                logger.error(f"Category update error: {str(e)}")
                messages.error(request, "Error updating category.")
    else:
        form = CategoryForm(instance=category)
    
    return render(request, 'store/dashboard/category_form.html', {
        'form': form,
        'category': category,
        'title': f'Edit {category.name}'
    })

@user_passes_test(is_admin)
@csrf_protect
def category_delete(request, pk):
    """Elimina categoría con confirmación"""
    category = get_object_or_404(Category, pk=pk)
    
    if request.method == 'POST':
        try:
            category_name = category.name
            category.delete()
            log_security_event("CATEGORY_DELETED", request.user.username, 
                             get_client_ip(request), f"Category: {category_name}")
            messages.success(request, f'Category "{category_name}" deleted successfully!')
            return redirect('category_list')
        except Exception as e:
            logger.error(f"Category deletion error: {str(e)}")
            messages.error(request, "Error deleting category.")
    
    return render(request, 'store/dashboard/category_confirm_delete.html', {'category': category})

# CRUD DE ÓRDENES
@user_passes_test(is_admin)
def order_list(request):
    """Lista órdenes para administración"""
    orders = Order.objects.all().order_by('-date_ordered')
    return render(request, 'store/dashboard/order_list.html', {'orders': orders})

@user_passes_test(is_admin)
def order_detail(request, pk):
    """Detalle de orden y sus productos"""
    order = get_object_or_404(Order, pk=pk)
    return render(request, 'store/dashboard/order_detail.html', {'order': order})

@user_passes_test(is_admin)
@csrf_protect
def order_update(request, pk):
    """Actualiza estado y dirección de orden"""
    order = get_object_or_404(Order, pk=pk)
    old_status = order.status
    
    if request.method == 'POST':
        form = OrderForm(request.POST, instance=order)
        if form.is_valid():
            new_status = form.cleaned_data['status']
            
            try:
                # Usar transacción atómica para asegurar consistencia
                with transaction.atomic():
                    # Si el pedido cambia de cancelado a otro estado, verificar disponibilidad de productos
                    if old_status == 'cancelled' and new_status != 'cancelled':
                        order_items = OrderItem.objects.select_related('product').filter(order=order)
                        inventory_issue = False
                        
                        # Verificar disponibilidad de todos los productos
                        for item in order_items:
                            product = Product.objects.get(id=item.product.id)
                            if product.stock < item.quantity:
                                inventory_issue = True
                                messages.warning(request, f"Not enough stock available for {product.name}. Available: {product.stock}")
                        
                        # Si hay problemas de inventario, no permitir el cambio
                        if inventory_issue:
                            return redirect('order_detail', pk=order.pk)
                        
                        # Si no hay problemas, reducir el inventario nuevamente
                        for item in order_items:
                            product = Product.objects.get(id=item.product.id)
                            old_stock = product.stock
                            product.stock = max(0, product.stock - item.quantity)
                            if product.stock <= 0:
                                product.stock = 0
                                product.is_available = False
                            product.save()
                            logger.info(f"Order status changed from cancelled: Product {product.name}, Stock {old_stock} -> {product.stock}")
                    
                    # Si el pedido está siendo cancelado, devolvemos los productos al inventario
                    elif old_status != 'cancelled' and new_status == 'cancelled':
                        order_items = OrderItem.objects.select_related('product').filter(order=order)
                        for item in order_items:
                            product = Product.objects.get(id=item.product.id)
                            old_stock = product.stock
                            product.stock += item.quantity
                            product.is_available = True
                            product.save()
                            logger.info(f"Order cancelled: Product {product.name}, Stock {old_stock} -> {product.stock}")
                    
                    form.save()
                    log_security_event("ORDER_UPDATED", request.user.username, 
                                     get_client_ip(request), f"Order: {order.id}, Status: {new_status}")
                    messages.success(request, f'Order #{order.id} updated successfully!')
                    
                    # Si la solicitud es AJAX, devolver una respuesta JSON
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return JsonResponse({'status': 'success'})
                    return redirect('order_detail', pk=order.pk)
            
            except Exception as e:
                logger.error(f"Error updating order: {str(e)}")
                messages.error(request, "There was an error updating the order status. Please try again.")
                return redirect('order_detail', pk=order.pk)
    else:
        form = OrderForm(instance=order)
    
    return render(request, 'store/dashboard/order_form.html', {
        'form': form,
        'order': order,
        'title': f'Edit Order #{order.id}'
    })

@user_passes_test(is_admin)
@csrf_protect
def order_delete(request, pk):
    """Elimina orden con confirmación"""
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
                        logger.info(f"Order deleted: Product {product.name}, Stock {old_stock} -> {product.stock}")
                
                order_id = order.id
                order.delete()
                log_security_event("ORDER_DELETED", request.user.username, 
                                 get_client_ip(request), f"Order: {order_id}")
                messages.success(request, f'Order #{order_id} deleted successfully!')
                return redirect('order_list')
        
        except Exception as e:
            logger.error(f"Error deleting order: {str(e)}")
            messages.error(request, "There was an error deleting the order. Please try again.")
            return redirect('order_detail', pk=order.pk)
    
    return render(request, 'store/dashboard/order_confirm_delete.html', {'order': order})

@user_passes_test(is_admin)
@csrf_protect
def add_order_item(request, pk):
    """Añade producto a una orden"""
    order = get_object_or_404(Order, pk=pk)
    
    if request.method == 'POST':
        form = OrderItemForm(request.POST)
        if form.is_valid():
            product = form.cleaned_data['product']
            quantity = form.cleaned_data['quantity']
            
            try:
                with transaction.atomic():
                    product = Product.objects.get(id=product.id)
                    
                    # Verificar si hay suficiente stock
                    if product.stock < quantity and order.complete and order.status != 'cancelled':
                        messages.warning(request, f"Not enough stock available for {product.name}. Available: {product.stock}")
                        return redirect('order_detail', pk=order.pk)
                    
                    item = form.save(commit=False)
                    item.order = order
                    item.save()
                    
                    # Reducir el stock si la orden está completada y no cancelada
                    if order.complete and order.status != 'cancelled':
                        old_stock = product.stock
                        product.stock = max(0, product.stock - quantity)
                        if product.stock <= 0:
                            product.stock = 0
                            product.is_available = False
                        product.save()
                        logger.info(f"Item added to completed order: Product {product.name}, Stock {old_stock} -> {product.stock}")
                    
                    log_security_event("ORDER_ITEM_ADDED", request.user.username, 
                                     get_client_ip(request), f"Order: {order.id}, Product: {product.name}")
                    messages.success(request, 'Item added to the order successfully!')
                    return redirect('order_detail', pk=order.pk)
            
            except Exception as e:
                logger.error(f"Error adding order item: {str(e)}")
                messages.error(request, "There was an error adding the item to the order. Please try again.")
                return redirect('order_detail', pk=order.pk)
    else:
        form = OrderItemForm()
    
    return render(request, 'store/dashboard/order_item_form.html', {
        'form': form,
        'order': order,
        'title': f'Add Item to Order #{order.id}'
    })

@user_passes_test(is_admin)
@csrf_protect
def edit_order_item(request, pk):
    """Edita producto de una orden"""
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
                    
                    # Si la orden está completada y no cancelada, ajustar el inventario
                    if order.complete and order.status != 'cancelled':
                        quantity_difference = new_quantity - old_quantity
                        
                        # Verificar si hay suficiente stock para el aumento de cantidad
                        if quantity_difference > 0 and product.stock < quantity_difference:
                            messages.warning(request, f"Not enough stock available for {product.name}. Available: {product.stock}")
                            return redirect('order_detail', pk=order.pk)
                        
                        # Ajustar el inventario
                        old_stock = product.stock
                        product.stock = max(0, product.stock - quantity_difference)
                        if product.stock <= 0:
                            product.stock = 0
                            product.is_available = False
                        elif product.stock > 0:
                            product.is_available = True
                        product.save()
                        logger.info(f"Item edited in completed order: Product {product.name}, Stock {old_stock} -> {product.stock}")
                    
                    form.save()
                    log_security_event("ORDER_ITEM_UPDATED", request.user.username, 
                                     get_client_ip(request), f"Order: {order.id}, Product: {product.name}")
                    messages.success(request, 'Order item updated successfully!')
                    return redirect('order_detail', pk=item.order.pk)
            
            except Exception as e:
                logger.error(f"Error editing order item: {str(e)}")
                messages.error(request, "There was an error updating the order item. Please try again.")
                return redirect('order_detail', pk=order.pk)
    else:
        form = OrderItemForm(instance=item)
    
    return render(request, 'store/dashboard/order_item_form.html', {
        'form': form,
        'item': item,
        'order': item.order,
        'title': f'Edit Item in Order #{item.order.id}'
    })

@user_passes_test(is_admin)
@csrf_protect
def delete_order_item(request, pk):
    """Elimina producto de una orden"""
    item = get_object_or_404(OrderItem, pk=pk)
    order = item.order
    
    if request.method == 'POST':
        try:
            with transaction.atomic():
                # Si la orden está completada y no cancelada, restaurar el inventario
                if order.complete and order.status != 'cancelled':
                    product = Product.objects.get(id=item.product.id)
                    old_stock = product.stock
                    product.stock += item.quantity
                    product.is_available = True
                    product.save()
                    logger.info(f"Item deleted from completed order: Product {product.name}, Stock {old_stock} -> {product.stock}")
                
                item.delete()
                log_security_event("ORDER_ITEM_DELETED", request.user.username, 
                                 get_client_ip(request), f"Order: {order.id}, Product: {item.product.name}")
                messages.success(request, 'Order item removed successfully!')
                return redirect('order_detail', pk=order.pk)
        
        except Exception as e:
            logger.error(f"Error deleting order item: {str(e)}")
            messages.error(request, "There was an error removing the order item. Please try again.")
            return redirect('order_detail', pk=order.pk)
    
    return render(request, 'store/dashboard/order_item_confirm_delete.html', {
        'item': item,
        'order': order
    })

# VISTAS DE CUENTA DE USUARIO
@login_required
@csrf_protect
def my_account(request):
    """Gestiona perfil del usuario con validaciones"""
    customer = request.user.customer
    
    if request.method == 'POST':
        try:
            # Validar y sanitizar entradas
            first_name = validate_text_input(request.POST.get('first_name', ''), "first name", 30)
            last_name = validate_text_input(request.POST.get('last_name', ''), "last name", 30)
            email = validate_text_input(request.POST.get('email', ''), "email", 254)
            phone = validate_text_input(request.POST.get('phone', ''), "phone", 15)
            address = validate_text_input(request.POST.get('address', ''), "address", 500)
            
            # Validar email format
            import re
            if email and not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                raise ValidationError("Invalid email format")
            
            # Verificar unicidad del email
            if email and User.objects.filter(email__iexact=email).exclude(pk=request.user.pk).exists():
                raise ValidationError("A user with this email already exists")
            
            with transaction.atomic():
                # Actualizar usuario
                user = request.user
                user.first_name = first_name
                user.last_name = last_name
                user.email = email
                user.save()
                
                # Actualizar cliente
                customer.phone = phone
                customer.address = address
                customer.save()
                
                log_security_event("ACCOUNT_UPDATED", request.user.username, 
                                 get_client_ip(request))
                messages.success(request, "Your account information has been updated successfully!")
                return redirect('my_account')
        
        except ValidationError as e:
            messages.error(request, str(e))
        except Exception as e:
            logger.error(f"Account update error: {str(e)}")
            messages.error(request, "Error updating account information.")
    
    context = {
        'user': request.user,
        'customer': customer
    }
    return render(request, 'store/my_account.html', context)

@login_required
def my_orders(request):
    """Lista pedidos del usuario"""
    customer = request.user.customer
    orders = Order.objects.filter(customer=customer).order_by('-date_ordered')
    
    context = {
        'orders': orders
    }
    return render(request, 'store/my_orders.html', context)

@login_required
def order_customer_detail(request, pk):
    """Detalle de pedido específico con validación de ownership"""
    try:
        if not isinstance(pk, int) or pk <= 0:
            raise ValidationError("Invalid order ID")
            
        customer = request.user.customer
        order = get_object_or_404(Order, pk=pk, customer=customer)  # Asegurar que el pedido pertenece al cliente
        
        context = {
            'order': order
        }
        return render(request, 'store/order_customer_detail.html', context)
    
    except Exception as e:
        logger.error(f"Error in customer order detail: {str(e)}")
        messages.error(request, "Order not found.")
        return redirect('my_orders')

# Vista para manejar errores CSRF
def csrf_failure(request, reason=""):
    """Vista personalizada para fallos CSRF"""
    log_security_event("CSRF_FAILURE", 
                     request.user.username if request.user.is_authenticated else "anonymous", 
                     get_client_ip(request), reason)
    return render(request, 'store/csrf_error.html', {'reason': reason}, status=403)