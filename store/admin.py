# store/admin.py
from django.contrib import admin
from django.utils.html import format_html
from .models import Category, Product, Customer, Order, OrderItem
import logging

logger = logging.getLogger('store')

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    """Configuración segura del admin para categorías"""
    list_display = ['name', 'description', 'product_count']
    search_fields = ['name']
    list_per_page = 25
    
    def product_count(self, obj):
        return obj.products.count()
    product_count.short_description = 'Products'

@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    """Configuración segura del admin para productos"""
    list_display = ['name', 'category', 'price', 'stock', 'is_available', 'roast_level', 'format']
    list_filter = ['category', 'roast_level', 'format', 'is_available', 'created_at']
    search_fields = ['name', 'description', 'origin']
    list_editable = ['price', 'stock', 'is_available']
    list_per_page = 25
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'category', 'description', 'image')
        }),
        ('Pricing & Inventory', {
            'fields': ('price', 'stock', 'is_available')
        }),
        ('Coffee Details', {
            'fields': ('roast_level', 'origin', 'format', 'weight')
        }),
    )
    
    def save_model(self, request, obj, form, change):
        """Log changes para auditoría"""
        action = 'updated' if change else 'created'
        super().save_model(request, obj, form, change)
        logger.info(f"Product {action}: {obj.name} by admin {request.user.username}")

@admin.register(Customer)
class CustomerAdmin(admin.ModelAdmin):
    """Configuración segura del admin para clientes"""
    list_display = ['user', 'phone', 'order_count']
    search_fields = ['user__username', 'user__email', 'phone']
    list_per_page = 25
    
    def order_count(self, obj):
        return obj.orders.count()
    order_count.short_description = 'Orders'

class OrderItemInline(admin.TabularInline):
    """Configuración para mostrar ítems dentro de órdenes"""
    model = OrderItem
    extra = 0
    readonly_fields = ['date_added']

@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    """Configuración segura del admin para órdenes"""
    list_display = ['id', 'customer', 'date_ordered', 'status', 'complete', 'total_display']
    list_filter = ['status', 'complete', 'date_ordered']
    search_fields = ['customer__user__username', 'transaction_id']
    inlines = [OrderItemInline]
    list_per_page = 25
    date_hierarchy = 'date_ordered'
    
    def total_display(self, obj):
        return f"${obj.get_cart_total}"
    total_display.short_description = 'Total'
    
    def save_model(self, request, obj, form, change):
        """Log changes para auditoría"""
        action = 'updated' if change else 'created'
        super().save_model(request, obj, form, change)
        logger.info(f"Order {action}: #{obj.id} by admin {request.user.username}")

@admin.register(OrderItem)
class OrderItemAdmin(admin.ModelAdmin):
    """Configuración del admin para ítems de órdenes"""
    list_display = ['product', 'order', 'quantity', 'subtotal_display', 'date_added']
    list_filter = ['date_added']
    search_fields = ['product__name', 'order__customer__user__username']
    list_per_page = 25
    
    def subtotal_display(self, obj):
        return f"${obj.get_total}"
    subtotal_display.short_description = 'Subtotal'

# Configuración adicional del admin site
admin.site.site_header = "Coffee Shop Administration"
admin.site.site_title = "Coffee Shop Admin"
admin.site.index_title = "Welcome to Coffee Shop Administration"