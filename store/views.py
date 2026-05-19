import time
import logging

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import JsonResponse, Http404
from django.db import transaction
from django.core.exceptions import PermissionDenied
from django.views.decorators.http import require_http_methods

from .models import Product, Category, Customer, Order, OrderItem
from .forms import (
    ProductForm, CategoryForm, LoginForm, RegistrationForm,
    OrderForm, OrderItemForm, ProfileUpdateForm, CheckoutForm,
)
from .decorators import ip_rate_limit, user_rate_limit

logger = logging.getLogger(__name__)


def admin_required(view_func):
    def _wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated or not request.user.is_staff:
            logger.warning('Acceso no autorizado al admin desde %s', request.META.get('REMOTE_ADDR'))
            raise PermissionDenied
        return view_func(request, *args, **kwargs)
    _wrapped.__name__ = view_func.__name__
    return _wrapped


# =============================================================================
# AUTENTICACIÓN
# =============================================================================

@ip_rate_limit('5/m', method='POST')
@require_http_methods(['GET', 'POST'])
def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard' if request.user.is_staff else 'store')

    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            user = authenticate(
                username=form.cleaned_data['username'],
                password=form.cleaned_data['password'],
            )
            if user is not None:
                login(request, user)
                logger.info('Login exitoso: %s desde %s', user.username, request.META.get('REMOTE_ADDR'))
                return redirect('dashboard' if user.is_staff else 'store')
            logger.warning('Login fallido para "%s" desde %s', form.cleaned_data.get('username'), request.META.get('REMOTE_ADDR'))
        else:
            logger.warning('Formulario de login inválido desde %s', request.META.get('REMOTE_ADDR'))
    else:
        form = LoginForm()

    return render(request, 'store/login.html', {'form': form})


@ip_rate_limit('3/h', method='POST')
@require_http_methods(['GET', 'POST'])
def register_view(request):
    if request.user.is_authenticated:
        return redirect('store')

    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_staff = False
            user.save()
            login(request, user)
            logger.info('Registro exitoso: %s desde %s', user.username, request.META.get('REMOTE_ADDR'))
            return redirect('store')
        logger.warning('Registro fallido desde %s', request.META.get('REMOTE_ADDR'))
    else:
        form = RegistrationForm()

    return render(request, 'store/register.html', {'form': form})


def logout_view(request):
    username = request.user.username if request.user.is_authenticated else 'Anonymous'
    logout(request)
    logger.info('Logout: %s', username)
    return redirect('login')


# =============================================================================
# TIENDA
# =============================================================================

def store(request):
    products = Product.objects.filter(is_available=True)
    categories = Category.objects.all()
    return render(request, 'store/store.html', {'products': products, 'categories': categories})


def customer_product_detail(request, pk):
    product = get_object_or_404(Product, pk=pk)
    related_products = Product.objects.filter(
        category=product.category, is_available=True
    ).exclude(pk=pk)[:4]
    return render(request, 'store/customer_product_detail.html', {
        'product': product,
        'related_products': related_products,
    })


def customer_category_detail(request, pk):
    category = get_object_or_404(Category, pk=pk)
    products = category.products.filter(is_available=True)
    return render(request, 'store/customer_category_detail.html', {
        'category': category,
        'products': products,
    })


# =============================================================================
# CARRITO
# =============================================================================

@login_required
@user_rate_limit('10/m', method='GET')
def add_to_cart(request, product_id):
    product = get_object_or_404(Product, id=product_id)

    if product.stock <= 0 or not product.is_available:
        messages.warning(request, f'Lo sentimos, {product.name} está agotado.')
        return redirect(request.META.get('HTTP_REFERER') or 'store')

    customer = request.user.customer
    order, _ = Order.objects.get_or_create(customer=customer, complete=False, defaults={'status': 'pending'})
    order_item, created = OrderItem.objects.get_or_create(order=order, product=product, defaults={'quantity': 1})

    if not created:
        if order_item.quantity < product.stock:
            order_item.quantity += 1
            order_item.save()
            messages.success(request, f'{product.name} añadido al carrito.')
        else:
            messages.warning(request, f'Solo hay {product.stock} unidad(es) disponible(s) de {product.name}.')
    else:
        messages.success(request, f'{product.name} añadido al carrito.')

    logger.info('%s añadió %s al carrito', request.user.username, product.name)
    return redirect(request.META.get('HTTP_REFERER') or 'customer_product_detail', pk=product_id)


@login_required
@user_rate_limit('20/m', method='GET')
def update_cart(request, product_id, action):
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
                    messages.success(request, 'Carrito actualizado.')
                else:
                    messages.warning(request, f'Solo hay {product.stock} unidad(es) disponible(s).')
            elif action == 'decrease':
                if order_item.quantity > 1:
                    order_item.quantity -= 1
                    order_item.save()
                    messages.success(request, 'Carrito actualizado.')
                else:
                    order_item.delete()
                    messages.success(request, f'{product.name} eliminado del carrito.')

    return redirect('cart')


@login_required
def remove_from_cart(request, product_id):
    product = get_object_or_404(Product, id=product_id)
    customer = request.user.customer
    order = Order.objects.filter(customer=customer, complete=False).first()

    if order:
        OrderItem.objects.filter(order=order, product=product).delete()
        messages.success(request, f'{product.name} eliminado del carrito.')
        logger.info('%s eliminó %s del carrito', request.user.username, product.name)

    return redirect('cart')


@login_required
def cart(request):
    customer = request.user.customer
    order = Order.objects.filter(customer=customer, complete=False).first()

    if order:
        cart_items = order.orderitem_set.all()
        cart_total = order.get_cart_total
    else:
        cart_items = []
        cart_total = 0

    return render(request, 'store/cart.html', {'cart_items': cart_items, 'cart_total': cart_total})


# =============================================================================
# CHECKOUT
# =============================================================================

@login_required
@user_rate_limit('2/m', method='POST')
def checkout(request):
    try:
        customer = request.user.customer
    except Exception:
        messages.error(request, 'Error con tu cuenta. Inicia sesión de nuevo.')
        return redirect('login')

    order = Order.objects.filter(customer=customer, complete=False).first()

    if request.method == 'POST':
        form = CheckoutForm(request.POST)
        if form.is_valid():
            if not order:
                messages.error(request, 'Tu carrito está vacío.')
                return redirect('cart')

            try:
                with transaction.atomic():
                    order_items = OrderItem.objects.select_related('product').filter(order=order)

                    if not order_items.exists():
                        messages.error(request, 'Tu carrito está vacío.')
                        return redirect('cart')

                    # Verificar stock
                    for item in order_items:
                        product = Product.objects.select_for_update().get(id=item.product.id)
                        if item.quantity > product.stock or not product.is_available:
                            messages.warning(
                                request,
                                f'"{product.name}" ya no tiene suficiente stock. Disponible: {product.stock}',
                            )
                            return redirect('cart')

                    # Descontar stock
                    for item in order_items:
                        product = Product.objects.select_for_update().get(id=item.product.id)
                        product.stock = max(0, product.stock - item.quantity)
                        if product.stock == 0:
                            product.is_available = False
                        product.save()

                    d = form.cleaned_data
                    order.complete = True
                    order.status = 'processing'
                    order.transaction_id = f'TX-{int(time.time())}'
                    order.shipping_address = (
                        f"Nombre: {d['first_name']} {d['last_name']}\n"
                        f"Email: {d['email']}\n"
                        f"Teléfono: {d['phone']}\n"
                        f"Dirección: {d['shipping_address']}"
                    )
                    order.save()

                    logger.info('Orden #%s completada por %s', order.id, request.user.username)
                    messages.success(request, f'¡Orden #{order.id} realizada con éxito! Gracias por tu compra.')
                    return redirect('my_orders')

            except Exception as e:
                logger.error('Error en checkout para %s: %s', request.user.username, e)
                messages.error(request, 'Hubo un error procesando tu orden. Intenta de nuevo.')
                return redirect('cart')
        else:
            logger.warning('Checkout inválido para %s: %s', request.user.username, form.errors)
    else:
        initial = {
            'first_name': request.user.first_name,
            'last_name': request.user.last_name,
            'email': request.user.email,
            'phone': request.user.customer.phone,
        }
        form = CheckoutForm(initial=initial)

    if order:
        cart_items = order.orderitem_set.all()
        cart_total = order.get_cart_total
    else:
        cart_items = []
        cart_total = 0

    return render(request, 'store/checkout.html', {
        'form': form,
        'cart_items': cart_items,
        'cart_total': cart_total,
    })


# =============================================================================
# DASHBOARD ADMINISTRATIVO
# =============================================================================

@admin_required
def dashboard(request):
    context = {
        'product_count': Product.objects.count(),
        'category_count': Category.objects.count(),
        'order_count': Order.objects.filter(complete=True).count(),
        'products': Product.objects.all().order_by('-created_at')[:10],
        'orders': Order.objects.all().order_by('-date_ordered')[:10],
    }
    return render(request, 'store/dashboard/dashboard.html', context)


@admin_required
def user_list(request):
    users = User.objects.all().order_by('-date_joined')
    return render(request, 'store/dashboard/user_list.html', {'users': users})


# =============================================================================
# CRUD PRODUCTOS
# =============================================================================

@admin_required
def product_list(request):
    return render(request, 'store/dashboard/product_list.html', {'products': Product.objects.all()})


@admin_required
def product_detail(request, pk):
    product = get_object_or_404(Product, pk=pk)
    return render(request, 'store/dashboard/product_detail.html', {'product': product})


@admin_required
def product_create(request):
    if request.method == 'POST':
        form = ProductForm(request.POST, request.FILES)
        if form.is_valid():
            product = form.save()
            logger.info('Admin %s creó producto: %s', request.user.username, product.name)
            messages.success(request, f'Producto "{product.name}" creado.')
            return redirect('product_detail', pk=product.pk)
    else:
        form = ProductForm()

    return render(request, 'store/dashboard/product_form.html', {'form': form, 'title': 'Nuevo Producto'})


@admin_required
def product_update(request, pk):
    product = get_object_or_404(Product, pk=pk)

    if request.method == 'POST':
        form = ProductForm(request.POST, request.FILES, instance=product)
        if form.is_valid():
            product = form.save()
            if product.stock > 0:
                product.is_available = True
                product.save()
            logger.info('Admin %s actualizó producto: %s', request.user.username, product.name)
            messages.success(request, f'Producto "{product.name}" actualizado.')
            return redirect('product_detail', pk=product.pk)
    else:
        form = ProductForm(instance=product)

    return render(request, 'store/dashboard/product_form.html', {'form': form, 'product': product, 'title': f'Editar {product.name}'})


@admin_required
def product_delete(request, pk):
    product = get_object_or_404(Product, pk=pk)

    if request.method == 'POST':
        name = product.name
        product.delete()
        logger.info('Admin %s eliminó producto: %s', request.user.username, name)
        messages.success(request, f'Producto "{name}" eliminado.')
        return redirect('product_list')

    return render(request, 'store/dashboard/product_confirm_delete.html', {'product': product})


# =============================================================================
# CRUD CATEGORÍAS
# =============================================================================

@admin_required
def category_list(request):
    return render(request, 'store/dashboard/category_list.html', {'categories': Category.objects.all()})


@admin_required
def category_detail(request, pk):
    category = get_object_or_404(Category, pk=pk)
    return render(request, 'store/dashboard/category_detail.html', {
        'category': category,
        'products': category.products.all(),
    })


@admin_required
def category_create(request):
    if request.method == 'POST':
        form = CategoryForm(request.POST)
        if form.is_valid():
            category = form.save()
            logger.info('Admin %s creó categoría: %s', request.user.username, category.name)
            messages.success(request, f'Categoría "{category.name}" creada.')
            return redirect('category_detail', pk=category.pk)
    else:
        form = CategoryForm()

    return render(request, 'store/dashboard/category_form.html', {'form': form, 'title': 'Nueva Categoría'})


@admin_required
def category_update(request, pk):
    category = get_object_or_404(Category, pk=pk)

    if request.method == 'POST':
        form = CategoryForm(request.POST, instance=category)
        if form.is_valid():
            form.save()
            logger.info('Admin %s actualizó categoría: %s', request.user.username, category.name)
            messages.success(request, f'Categoría "{category.name}" actualizada.')
            return redirect('category_detail', pk=category.pk)
    else:
        form = CategoryForm(instance=category)

    return render(request, 'store/dashboard/category_form.html', {
        'form': form, 'category': category, 'title': f'Editar {category.name}',
    })


@admin_required
def category_delete(request, pk):
    category = get_object_or_404(Category, pk=pk)

    if request.method == 'POST':
        name = category.name
        category.delete()
        logger.info('Admin %s eliminó categoría: %s', request.user.username, name)
        messages.success(request, f'Categoría "{name}" eliminada.')
        return redirect('category_list')

    return render(request, 'store/dashboard/category_confirm_delete.html', {'category': category})


# =============================================================================
# CRUD ÓRDENES
# =============================================================================

@admin_required
def order_list(request):
    return render(request, 'store/dashboard/order_list.html', {'orders': Order.objects.all()})


@admin_required
def order_detail(request, pk):
    order = get_object_or_404(Order, pk=pk)
    return render(request, 'store/dashboard/order_detail.html', {'order': order})


@admin_required
def order_update(request, pk):
    order = get_object_or_404(Order, pk=pk)
    old_status = order.status

    if request.method == 'POST':
        form = OrderForm(request.POST, instance=order)
        if form.is_valid():
            new_status = form.cleaned_data['status']
            try:
                with transaction.atomic():
                    if old_status == 'cancelled' and new_status != 'cancelled':
                        for item in order.orderitem_set.select_related('product'):
                            product = Product.objects.select_for_update().get(id=item.product.id)
                            if product.stock < item.quantity:
                                messages.warning(request, f'Stock insuficiente para {product.name}.')
                                return redirect('order_detail', pk=order.pk)
                        for item in order.orderitem_set.select_related('product'):
                            product = Product.objects.select_for_update().get(id=item.product.id)
                            product.stock = max(0, product.stock - item.quantity)
                            product.is_available = product.stock > 0
                            product.save()

                    elif old_status != 'cancelled' and new_status == 'cancelled':
                        for item in order.orderitem_set.select_related('product'):
                            product = Product.objects.select_for_update().get(id=item.product.id)
                            product.stock += item.quantity
                            product.is_available = True
                            product.save()

                    form.save()
                    logger.info('Admin %s cambió orden #%s de %s a %s', request.user.username, order.id, old_status, new_status)
                    messages.success(request, f'Orden #{order.id} actualizada.')

                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return JsonResponse({'status': 'success'})
                    return redirect('order_detail', pk=order.pk)

            except Exception as e:
                logger.error('Error actualizando orden #%s: %s', order.id, e)
                messages.error(request, 'Error al actualizar la orden.')
                return redirect('order_detail', pk=order.pk)
    else:
        form = OrderForm(instance=order)

    return render(request, 'store/dashboard/order_form.html', {
        'form': form, 'order': order, 'title': f'Editar Orden #{order.id}',
    })


@admin_required
def order_delete(request, pk):
    order = get_object_or_404(Order, pk=pk)

    if request.method == 'POST':
        try:
            with transaction.atomic():
                if order.complete and order.status != 'cancelled':
                    for item in order.orderitem_set.select_related('product'):
                        product = Product.objects.select_for_update().get(id=item.product.id)
                        product.stock += item.quantity
                        product.is_available = True
                        product.save()
                order_id = order.id
                order.delete()
                logger.info('Admin %s eliminó orden #%s', request.user.username, order_id)
                messages.success(request, f'Orden #{order_id} eliminada.')
                return redirect('order_list')
        except Exception as e:
            logger.error('Error eliminando orden #%s: %s', order.id, e)
            messages.error(request, 'Error al eliminar la orden.')
            return redirect('order_detail', pk=order.pk)

    return render(request, 'store/dashboard/order_confirm_delete.html', {'order': order})


@admin_required
def add_order_item(request, pk):
    order = get_object_or_404(Order, pk=pk)

    if request.method == 'POST':
        form = OrderItemForm(request.POST)
        if form.is_valid():
            product = form.cleaned_data['product']
            quantity = form.cleaned_data['quantity']
            try:
                with transaction.atomic():
                    product = Product.objects.select_for_update().get(id=product.id)
                    if order.complete and order.status != 'cancelled' and product.stock < quantity:
                        messages.warning(request, f'Stock insuficiente para {product.name}.')
                        return redirect('order_detail', pk=order.pk)

                    item = form.save(commit=False)
                    item.order = order
                    item.save()

                    if order.complete and order.status != 'cancelled':
                        product.stock = max(0, product.stock - quantity)
                        product.is_available = product.stock > 0
                        product.save()

                    messages.success(request, 'Ítem añadido a la orden.')
                    return redirect('order_detail', pk=order.pk)
            except Exception as e:
                logger.error('Error añadiendo ítem a orden #%s: %s', order.id, e)
                messages.error(request, 'Error al añadir el ítem.')
                return redirect('order_detail', pk=order.pk)
    else:
        form = OrderItemForm()

    return render(request, 'store/dashboard/order_item_form.html', {
        'form': form, 'order': order, 'title': f'Añadir Ítem — Orden #{order.id}',
    })


@admin_required
def edit_order_item(request, pk):
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
                    if order.complete and order.status != 'cancelled':
                        diff = new_quantity - old_quantity
                        if diff > 0 and product.stock < diff:
                            messages.warning(request, f'Stock insuficiente para {product.name}.')
                            return redirect('order_detail', pk=order.pk)
                        product.stock = max(0, product.stock - diff)
                        product.is_available = product.stock > 0
                        product.save()
                    form.save()
                    messages.success(request, 'Ítem actualizado.')
                    return redirect('order_detail', pk=order.pk)
            except Exception as e:
                logger.error('Error editando ítem de orden #%s: %s', order.id, e)
                messages.error(request, 'Error al editar el ítem.')
                return redirect('order_detail', pk=order.pk)
    else:
        form = OrderItemForm(instance=item)

    return render(request, 'store/dashboard/order_item_form.html', {
        'form': form, 'item': item, 'order': order, 'title': f'Editar Ítem — Orden #{order.id}',
    })


@admin_required
def delete_order_item(request, pk):
    item = get_object_or_404(OrderItem, pk=pk)
    order = item.order

    if request.method == 'POST':
        try:
            with transaction.atomic():
                if order.complete and order.status != 'cancelled':
                    product = Product.objects.select_for_update().get(id=item.product.id)
                    product.stock += item.quantity
                    product.is_available = True
                    product.save()
                item.delete()
                messages.success(request, 'Ítem eliminado de la orden.')
                return redirect('order_detail', pk=order.pk)
        except Exception as e:
            logger.error('Error eliminando ítem de orden #%s: %s', order.id, e)
            messages.error(request, 'Error al eliminar el ítem.')
            return redirect('order_detail', pk=order.pk)

    return render(request, 'store/dashboard/order_item_confirm_delete.html', {'item': item, 'order': order})


# =============================================================================
# CUENTA DE USUARIO
# =============================================================================

@login_required
@user_rate_limit('5/m', method='POST')
def my_account(request):
    try:
        customer = request.user.customer
    except Exception:
        messages.error(request, 'Error cargando tu perfil.')
        return redirect('store')

    if request.method == 'POST':
        form = ProfileUpdateForm(request.POST, instance=request.user)
        if form.is_valid():
            try:
                form.save()
                phone = form.cleaned_data.get('phone', '').strip()
                address = form.cleaned_data.get('address', '').strip()
                if phone:
                    customer.phone = phone
                if address:
                    customer.address = address
                customer.save()
                logger.info('%s actualizó su perfil', request.user.username)
                messages.success(request, 'Perfil actualizado correctamente.')
                return redirect('my_account')
            except Exception as e:
                logger.error('Error guardando perfil de %s: %s', request.user.username, e)
                messages.error(request, 'Error al guardar los datos.')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f'{field.replace("_", " ").title()}: {error}')
    else:
        try:
            phone_value = customer.phone if customer.encrypted_phone else ''
            address_value = customer.address if customer.encrypted_address else ''
        except Exception:
            phone_value = ''
            address_value = ''
        form = ProfileUpdateForm(instance=request.user, initial={'phone': phone_value, 'address': address_value})

    return render(request, 'store/my_account.html', {'form': form, 'customer': customer})


@login_required
def my_orders(request):
    orders = Order.objects.filter(customer=request.user.customer).order_by('-date_ordered')
    return render(request, 'store/my_orders.html', {'orders': orders})


@login_required
def order_customer_detail(request, pk):
    order = get_object_or_404(Order, pk=pk, customer=request.user.customer)
    return render(request, 'store/order_customer_detail.html', {'order': order})
