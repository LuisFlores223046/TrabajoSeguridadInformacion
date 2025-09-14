from django.contrib import admin
from .models import Category, Product, Customer, Order, OrderItem

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    """Configuración del admin para categorías"""
    list_display = ['name', 'description']  # Columnas a mostrar
    search_fields = ['name']  # Campos de búsqueda

@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    """Configuración del admin para productos"""
    list_display = ['name', 'category', 'price', 'stock', 'is_available', 'roast_level', 'format']
    list_filter = ['category', 'roast_level', 'format', 'is_available']  # Filtros laterales
    search_fields = ['name', 'description', 'origin']
    list_editable = ['price', 'stock', 'is_available']  # Campos editables en la lista

@admin.register(Customer)
class CustomerAdmin(admin.ModelAdmin):
    """Configuración del admin para clientes"""
    list_display = ['user', 'phone']
    search_fields = ['user__username', 'user__email', 'phone']

class OrderItemInline(admin.TabularInline):
    """Configuración para mostrar ítems dentro de órdenes"""
    model = OrderItem
    extra = 0  # No mostrar filas adicionales vacías

@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    """Configuración del admin para órdenes"""
    list_display = ['id', 'customer', 'date_ordered', 'status', 'complete']
    list_filter = ['status', 'complete', 'date_ordered']
    search_fields = ['customer__user__username', 'transaction_id']
    inlines = [OrderItemInline]  # Mostrar ítems dentro de la orden

@admin.register(OrderItem)
class OrderItemAdmin(admin.ModelAdmin):
    """Configuración del admin para ítems de órdenes"""
    list_display = ['product', 'order', 'quantity', 'date_added']
    list_filter = ['date_added']
    search_fields = ['product__name', 'order__customer__user__username']