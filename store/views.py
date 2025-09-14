# store/views.py - ARCHIVO COMPLETO CON SEGURIDAD MEJORADA
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.http import JsonResponse, Http404
from django.db import transaction, IntegrityError
from django.core.exceptions import ValidationError, PermissionDenied
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods, require_POST
from django.utils.html import escape
from django.db.models import Q
from django.views.decorators.cache import never_cache

# CORRECCIÓN: Importar django-ratelimit correctamente
try:
    from django_ratelimit.decorators import ratelimit
except ImportError:
    # Si no está instalado, crear un decorador dummy
    def ratelimit(key=None, rate=None, method=None, **kwargs):
        def decorator(func):
            return func
        return decorator

import time
import logging
import json
import re
import html

from .models import Product, Category, Customer, Order, OrderItem
from .forms import ProductForm, CategoryForm, LoginForm, RegistrationForm, OrderForm, OrderItemForm, UserProfileForm

# Configurar logging para seguridad
security_logger = logging.getLogger('security')
logger = logging.getLogger(__name__)

def track_security_event(event_type, user, details):
    """Rastrea eventos de seguridad específicos"""
    security_logger.warning(f"SECURITY_EVENT: {event_type} - User: {user} - Details: {details}")

def handle_errors(view_func):
    """Decorador para manejo centralizado de errores"""
    def wrapper(request, *args, **kwargs):
        try:
            return view_func(request, *args, **kwargs)
        except ValidationError as e:
            logger.warning(f"Validation error in {view_func.__name__}: {str(e)}")
            messages.error(request, "Invalid input provided. Please check your data.")
            return redirect('store')
        except PermissionDenied:
            logger.warning(f"Permission denied in {view_func.__name__} for user {request.user}")
            track_security_event("PERMISSION_DENIED", request.user, f"View: {view_func.__name__}")
            messages.error(request, "You don't have permission to perform this action.")
            return redirect('store')
        except IntegrityError as e:
            logger.error(f"Database integrity error in {view_func.__name__}: {str(e)}")
            messages.error(request, "Database error occurred. Please try again.")
            return redirect('store')
        except Exception as e:
            logger.error(f"Unexpected error in {view_func.__name__}: {str(e)}")
            messages.error(request, "An unexpected error occurred. Please try again.")
            return redirect('store')
    return wrapper

def is_admin(user):
    """Verifica permisos de administrador de forma segura."""
    return user.is_authenticated and user.is_staff

def sanitize_search_input(search_term):
    """Sanitiza términos de búsqueda para prevenir inyección SQL y XSS"""
    if not search_term:
        return ""
    
    # Escapar HTML y limitar caracteres
    cleaned = html.escape(search_term.strip())
    
    # Remover caracteres peligrosos para SQL
    dangerous_chars = ["'", '"', ';', '--', '/*', '*/', 'xp_', 'sp_', 'exec', 'execute', 
                      'union', 'select', 'insert', 'update', 'delete', 'drop', 'create',
                      '<script', '</script>', 'javascript:', 'vbscript:', 'onload=', 'onerror=']
    
    cleaned_lower = cleaned.lower()
    for char in dangerous_chars:
        if char in cleaned_lower:
            logger.warning(f"Potential injection attempt blocked: {search_term}")
            track_security_event("INJECTION_ATTEMPT", "Anonymous", f"Search term: {search_term}")
            return ""
    
    # Remover patrones de script
    script_patterns = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'on\w+\s*=',
        r'<.*?>'
    ]
    
    for pattern in script_patterns:
        cleaned = re.sub(pattern, '', cleaned, flags=re.IGNORECASE | re.DOTALL)
    
    # Limitar longitud
    return cleaned[:100]

def validate_user_input(input_string, field_name="input", max_length=200):
    """Validación centralizada de entrada de usuario"""
    if not input_string:
        return ""
    
    # Escapar HTML
    cleaned = html.escape(input_string.strip())
    
    # Verificar longitud
    if len(cleaned) > max_length:
        raise ValidationError(f"{field_name} exceeds maximum length of {max_length} characters.")
    
    # Verificar caracteres peligrosos
    dangerous_patterns = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'on\w+\s*=',
        r'<iframe[^>]*>.*?</iframe>',
        r'<object[^>]*>.*?</object>',
        r'<embed[^>]*>.*?</embed>',
        r'<link[^>]*>',
        r'<meta[^>]*>'
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, cleaned, re.IGNORECASE):
            raise ValidationError(f"Invalid characters detected in {field_name}.")
    
    return cleaned

# ==============================================
# VISTAS DE AUTENTICACIÓN
# ==============================================

@csrf_protect
@require_http_methods(["GET", "POST"])
@handle_errors
@ratelimit(key='ip', rate='5/m', method='POST')
@never_cache
def login_view(request):
    """Procesa inicio de sesión con protecciones adicionales."""
    if request.user.is_authenticated:
        return redirect('dashboard' if request.user.is_staff else 'store')
    
    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        
        # Validaciones adicionales antes de procesar
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        
        # Validar entrada básica
        if not username or not password:
            messages.error(request, "Both username and password are required.")
            return render(request, 'store/login.html', {'form': LoginForm()})
        
        # Sanitizar username
        try:
            username = validate_user_input(username, "username", 150)
        except ValidationError as e:
            messages.error(request, str(e))
            track_security_event("INVALID_LOGIN_INPUT", "Anonymous", f"Username: {username}")
            return render(request, 'store/login.html', {'form': LoginForm()})
        
        if form.is_valid():
            user = authenticate(username=username, password=password)
            if user is not None:
                if user.is_active:
                    login(request, user)
                    logger.info(f"Successful login for user: {username}")
                    
                    # Redirección segura
                    next_url = request.GET.get('next')
                    if next_url and next_url.startswith('/') and not next_url.startswith('//'):
                        return redirect(next_url)
                    
                    return redirect('dashboard' if user.is_staff else 'store')
                else:
                    logger.warning(f"Login attempt for inactive user: {username}")
                    track_security_event("INACTIVE_USER_LOGIN", username, "Account disabled")
                    messages.error(request, "Your account has been disabled.")
            else:
                logger.warning(f"Failed login attempt for username: {username}")
                track_security_event("FAILED_LOGIN", username, f"IP: {request.META.get('REMOTE_ADDR', 'Unknown')}")
                messages.error(request, "Invalid username or password.")
        else:
            logger.warning(f"Invalid form submission in login: {form.errors}")
            track_security_event("INVALID_LOGIN_FORM", "Anonymous", f"Errors: {form.errors}")
    else:
        form = LoginForm()
    
    return render(request, 'store/login.html', {'form': form})

@csrf_protect
@require_http_methods(["GET", "POST"])
@handle_errors
@ratelimit(key='ip', rate='3/m', method='POST')
def register_view(request):
    """Procesa registro de nuevos usuarios con validaciones mejoradas."""
    if request.user.is_authenticated:
        return redirect('store')
    
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            try:
                with transaction.atomic():
                    # Validaciones adicionales antes de crear el usuario
                    username = form.cleaned_data['username']
                    email = form.cleaned_data['email']
                    
                    # Verificar que no existan usuarios con el mismo email o username
                    if User.objects.filter(username__iexact=username).exists():
                        messages.error(request, "Username already exists.")
                        return render(request, 'store/register.html', {'form': form})
                    
                    if User.objects.filter(email__iexact=email).exists():
                        messages.error(request, "Email already registered.")
                        return render(request, 'store/register.html', {'form': form})
                    
                    user = form.save(commit=False)
                    user.is_staff = False  # Asegurar que no sea staff por defecto
                    user.is_superuser = False  # Asegurar que no sea superuser
                    user.save()
                    
                    logger.info(f"New user registered: {user.username}")
                    login(request, user)
                    messages.success(request, "Account created successfully!")
                    return redirect('store')
                    
            except IntegrityError:
                logger.warning(f"Registration attempt with existing data")
                messages.error(request, "User already exists. Please choose different credentials.")
        else:
            logger.warning(f"Invalid registration form: {form.errors}")
    else:
        form = RegistrationForm()
    
    return render(request, 'store/register.html', {'form': form})

@require_POST
@csrf_protect
def logout_view(request):
    """Cierra sesión de forma segura."""
    username = request.user.username if request.user.is_authenticated else "Anonymous"
    logout(request)
    logger.info(f"User logged out: {username}")
    messages.success(request, "You have been logged out successfully.")
    return redirect('login')

# ==============================================
# VISTAS PRINCIPALES DE LA TIENDA
# ==============================================

@handle_errors
def store(request):
    """Muestra productos y categorías con búsqueda segura mejorada."""
    try:
        # Manejo seguro de parámetros de búsqueda
        search_query = request.GET.get('search', '')
        category_filter = request.GET.get('category', '')
        
        # Sanitizar entradas
        if search_query:
            try:
                search_query = sanitize_search_input(search_query)
            except Exception as e:
                logger.warning(f"Error sanitizing search query: {str(e)}")
                search_query = ""
        
        # Construir queryset base
        products = Product.objects.filter(is_available=True).select_related('category')
        
        # Aplicar filtros de forma segura
        if search_query:
            products = products.filter(
                Q(name__icontains=search_query) | 
                Q(description__icontains=search_query) |
                Q(origin__icontains=search_query)
            )
        
        # Validar category_filter
        if category_filter:
            try:
                category_id = int(category_filter)
                if category_id > 0:
                    products = products.filter(category_id=category_id)
            except (ValueError, TypeError):
                logger.warning(f"Invalid category filter: {category_filter}")
                category_filter = ""
        
        categories = Category.objects.all()
        
        context = {
            'products': products[:20],  # Limitar resultados
            'categories': categories,
            'search_query': search_query,
            'selected_category': category_filter
        }
        
        return render(request, 'store/store.html', context)
        
    except Exception as e:
        logger.error(f"Error in store view: {str(e)}")
        messages.error(request, "Error loading products. Please try again.")
        return render(request, 'store/store.html', {
            'products': Product.objects.filter(is_available=True)[:10],
            'categories': Category.objects.all()
        })

def customer_product_detail(request, pk):
    """Muestra detalle de producto con validación de ID."""
    try:
        pk = int(pk)
        if pk <= 0:
            raise Http404("Invalid product ID")
    except (ValueError, TypeError):
        raise Http404("Invalid product ID")
    
    product = get_object_or_404(Product, pk=pk, is_available=True)
    related_products = Product.objects.filter(
        category=product.category, 
        is_available=True
    ).exclude(pk=pk)[:4]
    
    context = {
        'product': product,
        'related_products': related_products
    }
    return render(request, 'store/customer_product_detail.html', context)

def customer_category_detail(request, pk):
    """Muestra categoría con validación de ID."""
    try:
        pk = int(pk)
        if pk <= 0:
            raise Http404("Invalid category ID")
    except (ValueError, TypeError):
        raise Http404("Invalid category ID")
    
    category = get_object_or_404(Category, pk=pk)
    products = category.products.filter(is_available=True)
    
    context = {
        'category': category,
        'products': products
    }
    return render(request, 'store/customer_category_detail.html', context)

# ==============================================
# VISTAS DEL CARRITO DE COMPRAS
# ==============================================

@login_required
@require_POST
@csrf_protect
@handle_errors
@ratelimit(key='user', rate='30/m', method='POST')
def add_to_cart(request, product_id):
    """Añade producto al carrito con validaciones de seguridad mejoradas."""
    try:
        # Validar ID de producto más estrictamente
        try:
            product_id = int(product_id)
            if product_id <= 0:
                raise ValueError("Invalid product ID")
        except (ValueError, TypeError):
            raise ValidationError("Invalid product ID")
        
        product = get_object_or_404(Product, id=product_id, is_available=True)
        
        # Verificar stock
        if product.stock <= 0:
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
                    messages.success(request, f"{product.name} added to your cart.")
                else:
                    messages.warning(request, f"Sorry, we only have {product.stock} units available.")
            else:
                messages.success(request, f"{product.name} added to your cart.")
        
        return redirect(request.META.get('HTTP_REFERER', 'store'))
        
    except Exception as e:
        logger.error(f"Error adding to cart: {str(e)}")
        messages.error(request, "Error adding product to cart. Please try again.")
        return redirect('store')

@login_required
@handle_errors
def update_cart(request, product_id, action):
    """Actualiza cantidad de producto en carrito."""
    try:
        product_id = int(product_id)
        if product_id <= 0:
            raise ValueError("Invalid product ID")
    except (ValueError, TypeError):
        raise Http404("Invalid product ID")
    
    product = get_object_or_404(Product, id=product_id)
    customer = request.user.customer
    order = Order.objects.filter(customer=customer, complete=False).first()
    
    if order:
        order_item = OrderItem.objects.filter(order=order, product=product).first()
        
        if order_item:
            if action == 'increase':
                if order_item.quantity < product.stock:
                    order_item.quantity += 1
                    order_item.save()
                    messages.success(request, "Cart updated successfully.")
                else:
                    messages.warning(request, f"Sorry, we only have {product.stock} units of {product.name} available.")
            elif action == 'decrease':
                if order_item.quantity > 1:
                    order_item.quantity -= 1
                    order_item.save()
                    messages.success(request, "Cart updated successfully.")
                else:
                    order_item.delete()
                    messages.success(request, f"{product.name} removed from your cart.")
                    return redirect('cart')
    
    return redirect('cart')

@login_required
@handle_errors
def remove_from_cart(request, product_id):
    """Elimina producto del carrito."""
    try:
        product_id = int(product_id)
        if product_id <= 0:
            raise ValueError("Invalid product ID")
    except (ValueError, TypeError):
        raise Http404("Invalid product ID")
    
    product = get_object_or_404(Product, id=product_id)
    customer = request.user.customer
    order = Order.objects.filter(customer=customer, complete=False).first()
    
    if order:
        OrderItem.objects.filter(order=order, product=product).delete()
        messages.success(request, f"{product.name} removed from your cart.")
    
    return redirect('cart')

@login_required
@handle_errors
def cart(request):
    """Muestra carrito de compras actual."""
    customer = request.user.customer
    order = Order.objects.filter(customer=customer, complete=False).first()
    
    if order:
        cart_items = order.orderitem_set.select_related('product').all()
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
@handle_errors
@ratelimit(key='user', rate='3/m', method='POST')
def checkout(request):
    """Procesa checkout con validaciones de seguridad mejoradas."""
    try:
        customer = request.user.customer
        order = Order.objects.filter(customer=customer, complete=False).first()
        
        if request.method == 'POST':
            if not order or not order.orderitem_set.exists():
                messages.warning(request, "Your cart is empty.")
                return redirect('cart')
            
            # Validar dirección de envío con validación estricta
            shipping_address = request.POST.get('shipping_address', '').strip()
            if not shipping_address:
                messages.error(request, "Shipping address is required.")
                return redirect('checkout')
            
            # Sanitizar y validar dirección
            try:
                shipping_address = validate_user_input(shipping_address, "shipping address", 500)
                if len(shipping_address) < 10:
                    messages.error(request, "Please provide a complete shipping address.")
                    return redirect('checkout')
            except ValidationError as e:
                messages.error(request, f"Invalid shipping address: {str(e)}")
                return redirect('checkout')
            
            try:
                with transaction.atomic():
                    # Verificar inventario con bloqueo
                    order_items = OrderItem.objects.select_related('product').filter(order=order)
                    
                    for item in order_items:
                        product = Product.objects.select_for_update().get(id=item.product.id)
                        
                        if item.quantity > product.stock or not product.is_available:
                            messages.warning(
                                request, 
                                f"Sorry, {product.name} is no longer available in the requested quantity. Available: {product.stock}"
                            )
                            return redirect('cart')
                    
                    # Actualizar inventario
                    for item in order_items:
                        product = Product.objects.select_for_update().get(id=item.product.id)
                        product.stock = max(0, product.stock - item.quantity)
                        
                        if product.stock <= 0:
                            product.is_available = False
                        
                        product.save()
                        logger.info(f"Inventory updated: {product.name}, new stock: {product.stock}")
                    
                    # Completar orden
                    order.complete = True
                    order.status = 'processing'
                    order.transaction_id = f"TX-{int(time.time())}-{order.id}"
                    order.shipping_address = shipping_address
                    order.save()
                    
                    logger.info(f"Order completed: #{order.id} by user {request.user.username}")
                    messages.success(request, "Your order has been placed successfully!")
                    return redirect('my_orders')
                    
            except Exception as e:
                logger.error(f"Error in checkout: {str(e)}")
                messages.error(request, "There was an error processing your order. Please try again.")
                return redirect('cart')
        
        # Preparar datos para mostrar
        if order:
            cart_items = order.orderitem_set.select_related('product').all()
            cart_total = order.get_cart_total
        else:
            cart_items = []
            cart_total = 0
        
        context = {
            'cart_items': cart_items,
            'cart_total': cart_total
        }
        return render(request, 'store/checkout.html', context)
        
    except Exception as e:
        logger.error(f"Error in checkout view: {str(e)}")
        messages.error(request, "Error loading checkout page.")
        return redirect('cart')

# ==============================================
# VISTAS DE CUENTA DE USUARIO
# ==============================================

@login_required
@csrf_protect
@handle_errors
@ratelimit(key='user', rate='10/m', method='POST')
def my_account(request):
    """Gestiona perfil del usuario con validaciones de seguridad mejoradas."""
    try:
        customer = request.user.customer
        
        if request.method == 'POST':
            form = UserProfileForm(request.POST)
            if form.is_valid():
                try:
                    with transaction.atomic():
                        user = request.user
                        
                        # Validar que el email no esté en uso por otro usuario
                        email = form.cleaned_data['email']
                        existing_user = User.objects.filter(email__iexact=email).exclude(pk=user.pk)
                        if existing_user.exists():
                            messages.error(request, "This email is already in use by another account.")
                            return render(request, 'store/my_account.html', {'form': form})
                        
                        # Actualizar datos del usuario
                        user.first_name = form.cleaned_data['first_name']
                        user.last_name = form.cleaned_data['last_name']
                        user.email = email
                        user.save()
                        
                        # Actualizar datos del customer
                        customer.phone = form.cleaned_data['phone']
                        customer.address = form.cleaned_data['address']
                        customer.save()
                        
                        logger.info(f"User profile updated: {user.username}")
                        messages.success(request, "Your account information has been updated successfully!")
                        return redirect('my_account')
                        
                except Exception as e:
                    logger.error(f"Error updating user profile: {str(e)}")
                    messages.error(request, "Error updating profile. Please try again.")
            else:
                logger.warning(f"Invalid profile form: {form.errors}")
                messages.error(request, "Please correct the errors below.")
        else:
            initial_data = {
                'first_name': request.user.first_name,
                'last_name': request.user.last_name,
                'email': request.user.email,
                'phone': customer.phone or '',
                'address': customer.address or ''
            }
            form = UserProfileForm(initial=initial_data)
        
        context = {
            'form': form,
            'user': request.user,
            'customer': customer
        }
        return render(request, 'store/my_account.html', context)
        
    except Exception as e:
        logger.error(f"Error in my_account view: {str(e)}")
        messages.error(request, "Error loading account information.")
        return redirect('store')

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
    """Detalle de pedido específico con validación."""
    try:
        pk = int(pk)
        if pk <= 0:
            raise Http404("Invalid order ID")
    except (ValueError, TypeError):
        raise Http404("Invalid order ID")
    
    customer = request.user.customer
    order = get_object_or_404(Order, pk=pk, customer=customer)
    context = {
        'order': order
    }
    return render(request, 'store/order_customer_detail.html', context)

# ==============================================
# VISTAS DE ADMINISTRACIÓN
# ==============================================

@user_passes_test(is_admin)
@handle_errors
def dashboard(request):
    """Dashboard administrativo con estadísticas."""
    try:
        product_count = Product.objects.count()
        category_count = Category.objects.count()
        order_count = Order.objects.count()
        
        products = Product.objects.all().order_by('-created_at')[:10]
        orders = Order.objects.all().order_by('-date_ordered')[:10]
        
        context = {
            'product_count': product_count,
            'category_count': category_count,
            'order_count': order_count,
            'products': products,
            'orders': orders
        }
        return render(request, 'store/dashboard/dashboard.html', context)
    except Exception as e:
        logger.error(f"Error in dashboard: {str(e)}")
        messages.error(request, "Error loading dashboard.")
        return redirect('store')

@user_passes_test(is_admin)
def user_list(request):
    """Lista todos los usuarios registrados."""
    users = User.objects.all().order_by('-date_joined')
    return render(request, 'store/dashboard/user_list.html', {'users': users})

# ==============================================
# VISTAS CRUD DE PRODUCTOS
# ==============================================

@user_passes_test(is_admin)
def product_list(request):
    """Lista productos para administración."""
    products = Product.objects.all().select_related('category')
    return render(request, 'store/dashboard/product_list.html', {'products': products})

@user_passes_test(is_admin)
def product_detail(request, pk):
    """Detalle de producto para administración."""
    try:
        pk = int(pk)
        if pk <= 0:
            raise Http404("Invalid product ID")
    except (ValueError, TypeError):
        raise Http404("Invalid product ID")
    
    product = get_object_or_404(Product, pk=pk)
    return render(request, 'store/dashboard/product_detail.html', {'product': product})

@user_passes_test(is_admin)
@csrf_protect
@handle_errors
@ratelimit(key='user', rate='10/m', method='POST')
def product_create(request):
    """Crea nuevo producto con validaciones de seguridad mejoradas."""
    if request.method == 'POST':
        form = ProductForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                with transaction.atomic():
                    product = form.save()
                    logger.info(f"Product created: {product.name} by user {request.user.username}")
                    messages.success(request, f'Product "{product.name}" created successfully!')
                    return redirect('product_detail', pk=product.pk)
            except Exception as e:
                logger.error(f"Error creating product: {str(e)}")
                messages.error(request, "Error creating product. Please try again.")
        else:
            logger.warning(f"Invalid product form: {form.errors}")
    else:
        form = ProductForm()
    
    return render(request, 'store/dashboard/product_form.html', {
        'form': form,
        'title': 'New Coffee Product'
    })

@user_passes_test(is_admin)
@csrf_protect
@handle_errors
@ratelimit(key='user', rate='15/m', method='POST')
def product_update(request, pk):
    """Actualiza producto con validaciones."""
    try:
        pk = int(pk)
        if pk <= 0:
            raise Http404("Invalid product ID")
    except (ValueError, TypeError):
        raise Http404("Invalid product ID")
        
    product = get_object_or_404(Product, pk=pk)
    
    if request.method == 'POST':
        form = ProductForm(request.POST, request.FILES, instance=product)
        if form.is_valid():
            try:
                with transaction.atomic():
                    updated_product = form.save()
                    
                    if updated_product.stock > 0 and not updated_product.is_available:
                        updated_product.is_available = True
                        updated_product.save()
                    
                    logger.info(f"Product updated: {updated_product.name} by user {request.user.username}")
                    messages.success(request, f'Product "{updated_product.name}" updated successfully!')
                    return redirect('product_detail', pk=updated_product.pk)
            except Exception as e:
                logger.error(f"Error updating product: {str(e)}")
                messages.error(request, "Error updating product. Please try again.")
        else:
            logger.warning(f"Invalid product update form: {form.errors}")
    else:
        form = ProductForm(instance=product)
    
    return render(request, 'store/dashboard/product_form.html', {
        'form': form,
        'product': product,
        'title': f'Edit {product.name}'
    })

@user_passes_test(is_admin)
@handle_errors
def product_delete(request, pk):
    """Elimina producto con confirmación."""
    try:
        pk = int(pk)
        if pk <= 0:
            raise Http404("Invalid product ID")
    except (ValueError, TypeError):
        raise Http404("Invalid product ID")
    
    product = get_object_or_404(Product, pk=pk)
    
    if request.method == 'POST':
        product_name = product.name
        product.delete()
        logger.info(f"Product deleted: {product_name} by user {request.user.username}")
        messages.success(request, f'Product "{product_name}" deleted successfully!')
        return redirect('product_list')
    
    return render(request, 'store/dashboard/product_confirm_delete.html', {'product': product})

# ==============================================
# VISTAS CRUD DE CATEGORÍAS
# ==============================================

@user_passes_test(is_admin)
def category_list(request):
    """Lista categorías para administración."""
    categories = Category.objects.all()
    return render(request, 'store/dashboard/category_list.html', {'categories': categories})

@user_passes_test(is_admin)
def category_detail(request, pk):
    """Detalle de categoría y sus productos."""
    try:
        pk = int(pk)
        if pk <= 0:
            raise Http404("Invalid category ID")
    except (ValueError, TypeError):
        raise Http404("Invalid category ID")
    
    category = get_object_or_404(Category, pk=pk)
    products = category.products.all()
    return render(request, 'store/dashboard/category_detail.html', {
        'category': category,
        'products': products
    })

@user_passes_test(is_admin)
@csrf_protect
@handle_errors
@ratelimit(key='user', rate='10/m', method='POST')
def category_create(request):
    """Crea nueva categoría."""
    if request.method == 'POST':
        form = CategoryForm(request.POST)
        if form.is_valid():
            try:
                with transaction.atomic():
                    category = form.save()
                    logger.info(f"Category created: {category.name} by user {request.user.username}")
                    messages.success(request, f'Category "{category.name}" created successfully!')
                    return redirect('category_detail', pk=category.pk)
            except Exception as e:
                logger.error(f"Error creating category: {str(e)}")
                messages.error(request, "Error creating category. Please try again.")
        else:
            logger.warning(f"Invalid category form: {form.errors}")
    else:
        form = CategoryForm()
    
    return render(request, 'store/dashboard/category_form.html', {
        'form': form,
        'title': 'New Category'
    })

@user_passes_test(is_admin)
@csrf_protect
@handle_errors
@ratelimit(key='user', rate='15/m', method='POST')
def category_update(request, pk):
    """Actualiza categoría existente."""
    try:
        pk = int(pk)
        if pk <= 0:
            raise Http404("Invalid category ID")
    except (ValueError, TypeError):
        raise Http404("Invalid category ID")
    
    category = get_object_or_404(Category, pk=pk)
    
    if request.method == 'POST':
        form = CategoryForm(request.POST, instance=category)
        if form.is_valid():
            try:
                with transaction.atomic():
                    updated_category = form.save()
                    logger.info(f"Category updated: {updated_category.name} by user {request.user.username}")
                    messages.success(request, f'Category "{updated_category.name}" updated successfully!')
                    return redirect('category_detail', pk=updated_category.pk)
            except Exception as e:
                logger.error(f"Error updating category: {str(e)}")
                messages.error(request, "Error updating category. Please try again.")
        else:
            logger.warning(f"Invalid category update form: {form.errors}")
    else:
        form = CategoryForm(instance=category)
    
    return render(request, 'store/dashboard/category_form.html', {
        'form': form,
        'category': category,
        'title': f'Edit {category.name}'
    })

@user_passes_test(is_admin)
@handle_errors
def category_delete(request, pk):
    """Elimina categoría con confirmación."""
    try:
        pk = int(pk)
        if pk <= 0:
            raise Http404("Invalid category ID")
    except (ValueError, TypeError):
        raise Http404("Invalid category ID")
    
    category = get_object_or_404(Category, pk=pk)
    
    if request.method == 'POST':
        category_name = category.name
        category.delete()
        logger.info(f"Category deleted: {category_name} by user {request.user.username}")
        messages.success(request, f'Category "{category_name}" deleted successfully!')
        return redirect('category_list')
    
    return render(request, 'store/dashboard/category_confirm_delete.html', {'category': category})

# ==============================================
# VISTAS CRUD DE ÓRDENES
# ==============================================

@user_passes_test(is_admin)
def order_list(request):
    """Lista órdenes para administración."""
    orders = Order.objects.all().select_related('customer__user').order_by('-date_ordered')
    return render(request, 'store/dashboard/order_list.html', {'orders': orders})

@user_passes_test(is_admin)
def order_detail(request, pk):
    """Detalle de orden y sus productos."""
    try:
        pk = int(pk)
        if pk <= 0:
            raise Http404("Invalid order ID")
    except (ValueError, TypeError):
        raise Http404("Invalid order ID")
    
    order = get_object_or_404(Order, pk=pk)
    return render(request, 'store/dashboard/order_detail.html', {'order': order})

@user_passes_test(is_admin)
@csrf_protect
@handle_errors
@ratelimit(key='user', rate='20/m', method='POST')
def order_update(request, pk):
    """Actualiza estado y dirección de orden."""
    try:
        pk = int(pk)
        if pk <= 0:
            raise Http404("Invalid order ID")
    except (ValueError, TypeError):
        raise Http404("Invalid order ID")
    
    order = get_object_or_404(Order, pk=pk)
    old_status = order.status
    
    if request.method == 'POST':
        form = OrderForm(request.POST, instance=order)
        if form.is_valid():
            new_status = form.cleaned_data['status']
            
            try:
                with transaction.atomic():
                    # Manejar cambios de inventario según el estado
                    if old_status == 'cancelled' and new_status != 'cancelled':
                        # Orden se está reactivando - reducir inventario
                        order_items = OrderItem.objects.select_related('product').filter(order=order)
                        inventory_issue = False
                        
                        for item in order_items:
                            product = Product.objects.get(id=item.product.id)
                            if product.stock < item.quantity:
                                inventory_issue = True
                                messages.warning(request, f"Not enough stock available for {product.name}. Available: {product.stock}")
                        
                        if inventory_issue:
                            return redirect('order_detail', pk=order.pk)
                        
                        for item in order_items:
                            product = Product.objects.select_for_update().get(id=item.product.id)
                            old_stock = product.stock
                            product.stock = max(0, product.stock - item.quantity)
                            if product.stock <= 0:
                                product.stock = 0
                                product.is_available = False
                            product.save()
                            logger.info(f"Order uncancelled: Product {product.name}, old stock: {old_stock}, new stock: {product.stock}")
                    
                    elif old_status != 'cancelled' and new_status == 'cancelled':
                        # Orden se está cancelando - restaurar inventario
                        order_items = OrderItem.objects.select_related('product').filter(order=order)
                        for item in order_items:
                            product = Product.objects.select_for_update().get(id=item.product.id)
                            old_stock = product.stock
                            product.stock += item.quantity
                            product.is_available = True
                            product.save()
                            logger.info(f"Order cancelled: Product {product.name}, old stock: {old_stock}, new stock: {product.stock}")
                    
                    # Guardar orden
                    updated_order = form.save()
                    logger.info(f"Order #{order.id} updated by user {request.user.username}: {old_status} -> {new_status}")
                    messages.success(request, f'Order #{order.id} updated successfully!')
                    
                    # Responder con JSON si es una request AJAX
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return JsonResponse({'status': 'success'})
                    return redirect('order_detail', pk=order.pk)
            
            except Exception as e:
                logger.error(f"Error updating order: {str(e)}")
                messages.error(request, "There was an error updating the order status. Please try again.")
                return redirect('order_detail', pk=order.pk)
        else:
            logger.warning(f"Invalid order update form: {form.errors}")
    else:
        form = OrderForm(instance=order)
    
    return render(request, 'store/dashboard/order_form.html', {
        'form': form,
        'order': order,
        'title': f'Edit Order #{order.id}'
    })

@user_passes_test(is_admin)
@handle_errors
def order_delete(request, pk):
    """Elimina orden con confirmación."""
    try:
        pk = int(pk)
        if pk <= 0:
            raise Http404("Invalid order ID")
    except (ValueError, TypeError):
        raise Http404("Invalid order ID")
    
    order = get_object_or_404(Order, pk=pk)
    
    if request.method == 'POST':
        try:
            with transaction.atomic():
                # Restaurar inventario si la orden estaba completada
                if order.complete and order.status != 'cancelled':
                    order_items = OrderItem.objects.select_related('product').filter(order=order)
                    for item in order_items:
                        product = Product.objects.select_for_update().get(id=item.product.id)
                        old_stock = product.stock
                        product.stock += item.quantity
                        product.is_available = True
                        product.save()
                        logger.info(f"Order deleted: Product {product.name}, old stock: {old_stock}, new stock: {product.stock}")
                
                order_id = order.id
                order.delete()
                logger.info(f"Order #{order_id} deleted by user {request.user.username}")
                messages.success(request, f'Order #{order_id} deleted successfully!')
                return redirect('order_list')
        
        except Exception as e:
            logger.error(f"Error deleting order: {str(e)}")
            messages.error(request, "There was an error deleting the order. Please try again.")
            return redirect('order_detail', pk=order.pk)
    
    return render(request, 'store/dashboard/order_confirm_delete.html', {'order': order})

# ==============================================
# VISTAS DE GESTIÓN DE ÍTEMS DE ORDEN
# ==============================================

@user_passes_test(is_admin)
@csrf_protect
@handle_errors
@ratelimit(key='user', rate='15/m', method='POST')
def add_order_item(request, pk):
    """Añade producto a una orden."""
    try:
        pk = int(pk)
        if pk <= 0:
            raise Http404("Invalid order ID")
    except (ValueError, TypeError):
        raise Http404("Invalid order ID")
    
    order = get_object_or_404(Order, pk=pk)
    
    if request.method == 'POST':
        form = OrderItemForm(request.POST)
        if form.is_valid():
            product = form.cleaned_data['product']
            quantity = form.cleaned_data['quantity']
            
            try:
                with transaction.atomic():
                    # Verificar si ya existe el producto en la orden
                    existing_item = OrderItem.objects.filter(order=order, product=product).first()
                    if existing_item:
                        messages.warning(request, f"{product.name} is already in this order. Use edit to change quantity.")
                        return redirect('order_detail', pk=order.pk)
                    
                    product_obj = Product.objects.select_for_update().get(id=product.id)
                    
                    # Verificar stock si la orden está completada
                    if order.complete and order.status != 'cancelled':
                        if product_obj.stock < quantity:
                            messages.warning(request, f"Not enough stock available for {product_obj.name}. Available: {product_obj.stock}")
                            return redirect('order_detail', pk=order.pk)
                    
                    # Crear el item
                    item = form.save(commit=False)
                    item.order = order
                    item.save()
                    
                    # Actualizar inventario si es necesario
                    if order.complete and order.status != 'cancelled':
                        old_stock = product_obj.stock
                        product_obj.stock = max(0, product_obj.stock - quantity)
                        if product_obj.stock <= 0:
                            product_obj.stock = 0
                            product_obj.is_available = False
                        product_obj.save()
                        logger.info(f"Item added to completed order: Product {product_obj.name}, old stock: {old_stock}, new stock: {product_obj.stock}")
                    
                    logger.info(f"Order item added to order #{order.id} by user {request.user.username}")
                    messages.success(request, 'Item added to the order successfully!')
                    return redirect('order_detail', pk=order.pk)
            
            except Exception as e:
                logger.error(f"Error adding item: {str(e)}")
                messages.error(request, "There was an error adding the item to the order. Please try again.")
                return redirect('order_detail', pk=order.pk)
        else:
            logger.warning(f"Invalid order item form: {form.errors}")
    else:
        form = OrderItemForm()
    
    return render(request, 'store/dashboard/order_item_form.html', {
        'form': form,
        'order': order,
        'title': f'Add Item to Order #{order.id}'
    })

@user_passes_test(is_admin)
@csrf_protect
@handle_errors
@ratelimit(key='user', rate='15/m', method='POST')
def edit_order_item(request, pk):
    """Edita producto de una orden."""
    try:
        pk = int(pk)
        if pk <= 0:
            raise Http404("Invalid order item ID")
    except (ValueError, TypeError):
        raise Http404("Invalid order item ID")
    
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
                    product = Product.objects.select_for_update().get(id=product_id)
                    
                    # Calcular diferencia de inventario si la orden está completada
                    if order.complete and order.status != 'cancelled':
                        quantity_difference = new_quantity - old_quantity
                        
                        if quantity_difference > 0 and product.stock < quantity_difference:
                            messages.warning(request, f"Not enough stock available for {product.name}. Available: {product.stock}")
                            return redirect('order_detail', pk=order.pk)
                        
                        # Actualizar inventario
                        old_stock = product.stock
                        product.stock = max(0, product.stock - quantity_difference)
                        if product.stock <= 0:
                            product.stock = 0
                            product.is_available = False
                        elif product.stock > 0:
                            product.is_available = True
                        product.save()
                        logger.info(f"Item edited in completed order: Product {product.name}, old stock: {old_stock}, new stock: {product.stock}")
                    
                    # Guardar item
                    form.save()
                    logger.info(f"Order item edited in order #{order.id} by user {request.user.username}")
                    messages.success(request, 'Order item updated successfully!')
                    return redirect('order_detail', pk=item.order.pk)
            
            except Exception as e:
                logger.error(f"Error editing item: {str(e)}")
                messages.error(request, "There was an error updating the order item. Please try again.")
                return redirect('order_detail', pk=order.pk)
        else:
            logger.warning(f"Invalid order item edit form: {form.errors}")
    else:
        form = OrderItemForm(instance=item)
    
    return render(request, 'store/dashboard/order_item_form.html', {
        'form': form,
        'item': item,
        'order': item.order,
        'title': f'Edit Item in Order #{item.order.id}'
    })

@user_passes_test(is_admin)
@handle_errors
def delete_order_item(request, pk):
    """Elimina producto de una orden."""
    try:
        pk = int(pk)
        if pk <= 0:
            raise Http404("Invalid order item ID")
    except (ValueError, TypeError):
        raise Http404("Invalid order item ID")
    
    item = get_object_or_404(OrderItem, pk=pk)
    order = item.order
    
    if request.method == 'POST':
        try:
            with transaction.atomic():
                # Restaurar inventario si la orden está completada
                if order.complete and order.status != 'cancelled':
                    product = Product.objects.select_for_update().get(id=item.product.id)
                    old_stock = product.stock
                    product.stock += item.quantity
                    product.is_available = True
                    product.save()
                    logger.info(f"Item deleted from completed order: Product {product.name}, old stock: {old_stock}, new stock: {product.stock}")
                
                item.delete()
                logger.info(f"Order item deleted from order #{order.id} by user {request.user.username}")
                messages.success(request, 'Order item removed successfully!')
                return redirect('order_detail', pk=order.pk)
        
        except Exception as e:
            logger.error(f"Error deleting item: {str(e)}")
            messages.error(request, "There was an error removing the order item. Please try again.")
            return redirect('order_detail', pk=order.pk)
    
    return render(request, 'store/dashboard/order_item_confirm_delete.html', {
        'item': item,
        'order': order
    })