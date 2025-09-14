# store/views.py
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

import time
import logging
import json

from .models import Product, Category, Customer, Order, OrderItem
from .forms import ProductForm, CategoryForm, LoginForm, RegistrationForm, OrderForm, OrderItemForm, UserProfileForm

security_logger = logging.getLogger('security')

def track_security_event(event_type, user, details):
    """Rastrea eventos de seguridad específicos"""
    security_logger.warning(f"SECURITY_EVENT: {event_type} - User: {user} - Details: {details}")

# Configurar logging para seguridad
logger = logging.getLogger(__name__)

# Decorador de manejo de errores personalizado
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
    """Sanitiza términos de búsqueda para prevenir inyección SQL"""
    if not search_term:
        return ""
    
    # Escapar HTML y limitar caracteres
    cleaned = escape(search_term.strip())
    
    # Remover caracteres peligrosos para SQL
    dangerous_chars = ["'", '"', ';', '--', '/*', '*/', 'xp_', 'sp_', 'exec', 'execute', 
                      'union', 'select', 'insert', 'update', 'delete', 'drop', 'create']
    
    cleaned_lower = cleaned.lower()
    for char in dangerous_chars:
        if char in cleaned_lower:
            logger.warning(f"Potential SQL injection attempt: {search_term}")
            return ""
    
    # Limitar longitud
    return cleaned[:100]

# Vistas de autenticación securizadas
@csrf_protect
@require_http_methods(["GET", "POST"])
@handle_errors
@ratelimit(key='ip', rate='5/m', method='POST')
def login_view(request):
    """Procesa inicio de sesión con protecciones adicionales."""
    if request.user.is_authenticated:
        return redirect('dashboard' if request.user.is_staff else 'store')
    
    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            
            # Log intento de login
            logger.info(f"Login attempt for username: {username}")
            
            user = authenticate(username=username, password=password)
            if user is not None:
                if user.is_active:
                    login(request, user)
                    logger.info(f"Successful login for user: {username}")
                    
                    # Redirección segura
                    next_url = request.GET.get('next')
                    if next_url and next_url.startswith('/'):
                        return redirect(next_url)
                    
                    return redirect('dashboard' if user.is_staff else 'store')
                else:
                    logger.warning(f"Login attempt for inactive user: {username}")
                    messages.error(request, "Your account has been disabled.")
            else:
                logger.warning(f"Failed login attempt for username: {username}")
                messages.error(request, "Invalid username or password.")
        else:
            logger.warning(f"Invalid form submission in login: {form.errors}")
    else:
        form = LoginForm()
    
    return render(request, 'store/login.html', {'form': form})

@csrf_protect
@require_http_methods(["GET", "POST"])
@handle_errors
def register_view(request):
    """Procesa registro de nuevos usuarios con validaciones."""
    if request.user.is_authenticated:
        return redirect('store')
    
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            try:
                with transaction.atomic():
                    user = form.save()
                    user.is_staff = False  # Asegurar que no sea staff por defecto
                    user.save()
                    
                    logger.info(f"New user registered: {user.username}")
                    login(request, user)
                    messages.success(request, "Account created successfully!")
                    return redirect('store')
            except IntegrityError:
                logger.warning(f"Registration attempt with existing username: {form.cleaned_data.get('username')}")
                messages.error(request, "Username already exists. Please choose a different one.")
        else:
            logger.warning(f"Invalid registration form: {form.errors}")
    else:
        form = RegistrationForm()
    
    return render(request, 'store/register.html', {'form': form})

@require_POST
def logout_view(request):
    """Cierra sesión de forma segura."""
    username = request.user.username if request.user.is_authenticated else "Anonymous"
    logout(request)
    logger.info(f"User logged out: {username}")
    messages.success(request, "You have been logged out successfully.")
    return redirect('login')

# Vista principal de tienda con búsqueda segura
@handle_errors
def store(request):
    """Muestra productos y categorías con búsqueda segura."""
    try:
        # Manejo seguro de parámetros de búsqueda
        search_query = request.GET.get('search', '')
        category_filter = request.GET.get('category', '')
        
        # Sanitizar entradas
        search_query = sanitize_search_input(search_query)
        
        # Construir queryset base
        products = Product.objects.filter(is_available=True).select_related('category')
        
        # Aplicar filtros de forma segura
        if search_query:
            # Usar Q objects para búsqueda segura
            products = products.filter(
                Q(name__icontains=search_query) | 
                Q(description__icontains=search_query) |
                Q(origin__icontains=search_query)
            )
        
        if category_filter and category_filter.isdigit():
            products = products.filter(category_id=int(category_filter))
        
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
    """Muestra detalle de producto y productos relacionados."""
    product = get_object_or_404(Product, pk=pk)
    related_products = Product.objects.filter(category=product.category).exclude(pk=pk)[:4]
    context = {
        'product': product,
        'related_products': related_products
    }
    return render(request, 'store/customer_product_detail.html', context)

def customer_category_detail(request, pk):
    """Muestra categoría y sus productos disponibles."""
    category = get_object_or_404(Category, pk=pk)
    products = category.products.filter(is_available=True)
    context = {
        'category': category,
        'products': products
    }
    return render(request, 'store/customer_category_detail.html', context)

# Carrito con validaciones mejoradas
@login_required
@require_POST
@csrf_protect
@handle_errors
def add_to_cart(request, product_id):
    """Añade producto al carrito con validaciones de seguridad."""
    try:
        # Validar ID de producto
        if not str(product_id).isdigit() or product_id <= 0:
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
@handle_errors
def checkout(request):
    """Procesa checkout con validaciones de seguridad mejoradas."""
    try:
        customer = request.user.customer
        order = Order.objects.filter(customer=customer, complete=False).first()
        
        if request.method == 'POST':
            if not order or not order.orderitem_set.exists():
                messages.warning(request, "Your cart is empty.")
                return redirect('cart')
            
            # Validar dirección de envío
            shipping_address = request.POST.get('shipping_address', '').strip()
            if not shipping_address:
                messages.error(request, "Shipping address is required.")
                return redirect('checkout')
            
            # Sanitizar dirección
            from .validators import SecureInputValidator
            try:
                shipping_address = SecureInputValidator.validate_address(shipping_address)
            except ValidationError as e:
                messages.error(request, f"Invalid shipping address: {str(e)}")
                return redirect('checkout')
            
            try:
                with transaction.atomic():
                    # Verificar inventario
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

# Admin dashboard
@user_passes_test(is_admin)
@handle_errors
def dashboard(request):
    """Dashboard administrativo con estadísticas."""
    product_count = Product.objects.count()
    category_count = Category.objects.count()
    order_count = Order.objects.count()
    
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

@user_passes_test(is_admin)
def user_list(request):
    """Lista todos los usuarios registrados."""
    users = User.objects.all().order_by('-date_joined')
    return render(request, 'store/dashboard/user_list.html', {'users': users})

# Product CRUD operations
@user_passes_test(is_admin)
def product_list(request):
    """Lista productos para administración."""
    products = Product.objects.all()
    return render(request, 'store/dashboard/product_list.html', {'products': products})

@user_passes_test(is_admin)
def product_detail(request, pk):
    """Detalle de producto para administración."""
    product = get_object_or_404(Product, pk=pk)
    return render(request, 'store/dashboard/product_detail.html', {'product': product})

@user_passes_test(is_admin)
@csrf_protect
@handle_errors
def product_create(request):
    """Crea nuevo producto con validaciones de seguridad."""
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
def product_update(request, pk):
    """Actualiza producto con validaciones."""
    try:
        if not str(pk).isdigit() or pk <= 0:
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
        
    except Exception as e:
        logger.error(f"Error in product_update: {str(e)}")
        messages.error(request, "Error loading product. Please try again.")
        return redirect('product_list')

@user_passes_test(is_admin)
@handle_errors
def product_delete(request, pk):
    """Elimina producto con confirmación."""
    product = get_object_or_404(Product, pk=pk)
    
    if request.method == 'POST':
        product_name = product.name
        product.delete()
        messages.success(request, f'Product "{product_name}" deleted successfully!')
        return redirect('product_list')
    
    return render(request, 'store/dashboard/product_confirm_delete.html', {'product': product})

# Category CRUD operations
@user_passes_test(is_admin)
def category_list(request):
    """Lista categorías para administración."""
    categories = Category.objects.all()
    return render(request, 'store/dashboard/category_list.html', {'categories': categories})

@user_passes_test(is_admin)
def category_detail(request, pk):
    """Detalle de categoría y sus productos."""
    category = get_object_or_404(Category, pk=pk)
    products = category.products.all()
    return render(request, 'store/dashboard/category_detail.html', {
        'category': category,
        'products': products
    })

@user_passes_test(is_admin)
@csrf_protect
@handle_errors
def category_create(request):
    """Crea nueva categoría."""
    if request.method == 'POST':
        form = CategoryForm(request.POST)
        if form.is_valid():
            category = form.save()
            messages.success(request, f'Category "{category.name}" created successfully!')
            return redirect('category_detail', pk=category.pk)
    else:
        form = CategoryForm()
    
    return render(request, 'store/dashboard/category_form.html', {
        'form': form,
        'title': 'New Category'
    })

@user_passes_test(is_admin)
@csrf_protect
@handle_errors
def category_update(request, pk):
    """Actualiza categoría existente."""
    category = get_object_or_404(Category, pk=pk)
    
    if request.method == 'POST':
        form = CategoryForm(request.POST, instance=category)
        if form.is_valid():
            form.save()
            messages.success(request, f'Category "{category.name}" updated successfully!')
            return redirect('category_detail', pk=category.pk)
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
    category = get_object_or_404(Category, pk=pk)
    
    if request.method == 'POST':
        category_name = category.name
        category.delete()
        messages.success(request, f'Category "{category_name}" deleted successfully!')
        return redirect('category_list')
    
    return render(request, 'store/dashboard/category_confirm_delete.html', {'category': category})

# Order CRUD operations
@user_passes_test(is_admin)
def order_list(request):
    """Lista órdenes para administración."""
    orders = Order.objects.all()
    return render(request, 'store/dashboard/order_list.html', {'orders': orders})

@user_passes_test(is_admin)
def order_detail(request, pk):
    """Detalle de orden y sus productos."""
    order = get_object_or_404(Order, pk=pk)
    return render(request, 'store/dashboard/order_detail.html', {'order': order})

@user_passes_test(is_admin)
@csrf_protect
@handle_errors
def order_update(request, pk):
    """Actualiza estado y dirección de orden."""
    order = get_object_or_404(Order, pk=pk)
    old_status = order.status
    
    if request.method == 'POST':
        form = OrderForm(request.POST, instance=order)
        if form.is_valid():
            new_status = form.cleaned_data['status']
            
            try:
                with transaction.atomic():
                    if old_status == 'cancelled' and new_status != 'cancelled':
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
                            product = Product.objects.get(id=item.product.id)
                            old_stock = product.stock
                            product.stock = max(0, product.stock - item.quantity)
                            if product.stock <= 0:
                                product.stock = 0
                                product.is_available = False
                            product.save()
                            logger.info(f"Order uncancelled: Product {product.name}, old stock: {old_stock}, new stock: {product.stock}")
                    
                    elif old_status != 'cancelled' and new_status == 'cancelled':
                        order_items = OrderItem.objects.select_related('product').filter(order=order)
                        for item in order_items:
                            product = Product.objects.get(id=item.product.id)
                            old_stock = product.stock
                            product.stock += item.quantity
                            product.is_available = True
                            product.save()
                            logger.info(f"Order cancelled: Product {product.name}, old stock: {old_stock}, new stock: {product.stock}")
                    
                    form.save()
                    messages.success(request, f'Order #{order.id} updated successfully!')
                    
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
@handle_errors
def order_delete(request, pk):
    """Elimina orden con confirmación."""
    order = get_object_or_404(Order, pk=pk)
    
    if request.method == 'POST':
        try:
            with transaction.atomic():
                if order.complete and order.status != 'cancelled':
                    order_items = OrderItem.objects.select_related('product').filter(order=order)
                    for item in order_items:
                        product = Product.objects.get(id=item.product.id)
                        old_stock = product.stock
                        product.stock += item.quantity
                        product.is_available = True
                        product.save()
                        logger.info(f"Order deleted: Product {product.name}, old stock: {old_stock}, new stock: {product.stock}")
                
                order_id = order.id
                order.delete()
                messages.success(request, f'Order #{order_id} deleted successfully!')
                return redirect('order_list')
        
        except Exception as e:
            logger.error(f"Error deleting order: {str(e)}")
            messages.error(request, "There was an error deleting the order. Please try again.")
            return redirect('order_detail', pk=order.pk)
    
    return render(request, 'store/dashboard/order_confirm_delete.html', {'order': order})

@user_passes_test(is_admin)
@csrf_protect
@handle_errors
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
                    
                    if product.stock < quantity and order.complete and order.status != 'cancelled':
                        messages.warning(request, f"Not enough stock available for {product.name}. Available: {product.stock}")
                        return redirect('order_detail', pk=order.pk)
                    
                    item = form.save(commit=False)
                    item.order = order
                    item.save()
                    
                    if order.complete and order.status != 'cancelled':
                        old_stock = product.stock
                        product.stock = max(0, product.stock - quantity)
                        if product.stock <= 0:
                            product.stock = 0
                            product.is_available = False
                        product.save()
                        logger.info(f"Item added to completed order: Product {product.name}, old stock: {old_stock}, new stock: {product.stock}")
                    
                    messages.success(request, 'Item added to the order successfully!')
                    return redirect('order_detail', pk=order.pk)
            
            except Exception as e:
                logger.error(f"Error adding item: {str(e)}")
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
@handle_errors
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
                    
                    if order.complete and order.status != 'cancelled':
                        quantity_difference = new_quantity - old_quantity
                        
                        if quantity_difference > 0 and product.stock < quantity_difference:
                            messages.warning(request, f"Not enough stock available for {product.name}. Available: {product.stock}")
                            return redirect('order_detail', pk=order.pk)
                        
                        old_stock = product.stock
                        product.stock = max(0, product.stock - quantity_difference)
                        if product.stock <= 0:
                            product.stock = 0
                            product.is_available = False
                        elif product.stock > 0:
                            product.is_available = True
                        product.save()
                        logger.info(f"Item edited in completed order: Product {product.name}, old stock: {old_stock}, new stock: {product.stock}")
                    
                    form.save()
                    messages.success(request, 'Order item updated successfully!')
                    return redirect('order_detail', pk=item.order.pk)
            
            except Exception as e:
                logger.error(f"Error editing item: {str(e)}")
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
@handle_errors
def delete_order_item(request, pk):
    """Elimina producto de una orden."""
    item = get_object_or_404(OrderItem, pk=pk)
    order = item.order
    
    if request.method == 'POST':
        try:
            with transaction.atomic():
                if order.complete and order.status != 'cancelled':
                    product = Product.objects.get(id=item.product.id)
                    old_stock = product.stock
                    product.stock += item.quantity
                    product.is_available = True
                    product.save()
                    logger.info(f"Item deleted from completed order: Product {product.name}, old stock: {old_stock}, new stock: {product.stock}")
                
                item.delete()
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

@login_required
@csrf_protect
@handle_errors
def my_account(request):
    """Gestiona perfil del usuario con validaciones de seguridad."""
    try:
        customer = request.user.customer
        
        if request.method == 'POST':
            form = UserProfileForm(request.POST)
            if form.is_valid():
                try:
                    with transaction.atomic():
                        user = request.user
                        user.first_name = form.cleaned_data['first_name']
                        user.last_name = form.cleaned_data['last_name']
                        user.email = form.cleaned_data['email']
                        user.save()
                        
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
    """Detalle de pedido específico."""
    customer = request.user.customer
    order = get_object_or_404(Order, pk=pk, customer=customer)
    context = {
        'order': order
    }
    return render(request, 'store/order_customer_detail.html', context)