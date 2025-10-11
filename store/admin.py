from django.contrib import admin
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from .models import Category, Product, Customer, Order, OrderItem
import logging

logger = logging.getLogger(__name__)

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    """Configuración del admin para categorías"""
    list_display = ['name', 'description']
    search_fields = ['name']

@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    """Configuración del admin para productos"""
    list_display = ['name', 'category', 'price', 'stock', 'is_available', 'roast_level', 'format']
    list_filter = ['category', 'roast_level', 'format', 'is_available']
    search_fields = ['name', 'description', 'origin']
    list_editable = ['price', 'stock', 'is_available']


# ==================== FILTRO PERSONALIZADO ====================
class EncryptionStatusFilter(admin.SimpleListFilter):
    title = 'Estado de Cifrado'
    parameter_name = 'encryption_status'
    
    def lookups(self, request, model_admin):
        return (
            ('encrypted', '🔒 Cifrados'),
            ('not_encrypted', '⚠️ Sin cifrar'),
        )
    
    def queryset(self, request, queryset):
        if self.value() == 'encrypted':
            return queryset.exclude(encrypted_phone__isnull=True)
        if self.value() == 'not_encrypted':
            return queryset.filter(encrypted_phone__isnull=True)
        return queryset


@admin.register(Customer)
class CustomerAdmin(admin.ModelAdmin):
    """Admin de Customer con visualización limpia del cifrado"""
    
    list_display = ['id', 'user', 'phone_status', 'address_status']
    list_filter = [EncryptionStatusFilter, 'user__is_active']
    search_fields = ['user__username', 'user__email']
    
    readonly_fields = [
        'user',
        'show_encrypted_data',
    ]
    
    fieldsets = (
        ('👤 Usuario', {
            'fields': ('user',)
        }),
        ('🔒 Detalles Técnicos del Cifrado', {
            'fields': ('show_encrypted_data',),
            'classes': ('collapse',),
            'description': '⚠️ Expande para ver los datos técnicos de cómo se almacenan cifrados'
        }),
    )
    
    # ==================== LISTA ====================
    
    def phone_status(self, obj):
        if obj.encrypted_phone and obj.phone_key and obj.phone_iv:
            return format_html(
                '<span style="background: #28a745; color: white; padding: 5px 12px; '
                'border-radius: 4px; font-weight: bold; font-size: 12px;">✅ CIFRADO</span>'
            )
        return format_html(
            '<span style="background: #dc3545; color: white; padding: 5px 12px; '
            'border-radius: 4px; font-weight: bold; font-size: 12px;">❌ NO</span>'
        )
    phone_status.short_description = '📞 Teléfono'
    
    def address_status(self, obj):
        if obj.encrypted_address and obj.address_key and obj.address_iv:
            return format_html(
                '<span style="background: #28a745; color: white; padding: 5px 12px; '
                'border-radius: 4px; font-weight: bold; font-size: 12px;">✅ CIFRADO</span>'
            )
        return format_html(
            '<span style="background: #dc3545; color: white; padding: 5px 12px; '
            'border-radius: 4px; font-weight: bold; font-size: 12px;">❌ NO</span>'
        )
    address_status.short_description = '📍 Dirección'
    
    
    # ==================== DETALLES TÉCNICOS ====================
    
    def show_encrypted_data(self, obj):
        html = '<div style="font-family: monospace; font-size: 12px;">'
        
        # Teléfono
        html += '<div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px;">'
        html += '<h3 style="color: #495057; margin-top: 0;">📞 TELÉFONO - Campos en la BD</h3>'
        
        if obj.encrypted_phone:
            # Campo encrypted_phone
            html += '<div style="margin-bottom: 15px;">'
            html += '<strong style="color: #856404;">Campo (AES): encrypted_phone</strong><br>'
            html += '<div style="background: #fff; padding: 10px; border: 1px solid #dee2e6; border-radius: 4px; margin-top: 5px;">'
            html += f'<code style="word-break: break-all; color: #212529;">{obj.encrypted_phone}</code>'
            html += '</div>'
            html += f'<small style="color: #6c757d;">Tamaño: {len(obj.encrypted_phone)} caracteres</small>'
            html += '</div>'
            
            # Campo phone_key
            html += '<div style="margin-bottom: 15px;">'
            html += '<strong style="color: #0c5460;">Campo(RSA): phone_key</strong><br>'
            html += '<div style="background: #fff; padding: 10px; border: 1px solid #dee2e6; border-radius: 4px; margin-top: 5px;">'
            html += f'<code style="word-break: break-all; color: #212529;">{obj.phone_key}</code>'
            html += '</div>'
            html += f'<small style="color: #6c757d;">Tamaño: {len(obj.phone_key)} caracteres</small>'
            html += '</div>'
            
            # Campo phone_iv
            html += '<div>'
            html += '<strong style="color: #004085;">Campo(Auxiliar de AES): phone_iv</strong><br>'
            html += '<div style="background: #fff; padding: 10px; border: 1px solid #dee2e6; border-radius: 4px; margin-top: 5px;">'
            html += f'<code style="color: #212529;">{obj.phone_iv}</code>'
            html += '</div>'
            html += f'<small style="color: #6c757d;">Tamaño: {len(obj.phone_iv)} caracteres</small>'
            html += '</div>'
        else:
            html += '<p style="color: #dc3545;">❌ No hay datos cifrados</p>'
        
        html += '</div>'
        
        # Dirección
        html += '<div style="background: #f8f9fa; padding: 20px; border-radius: 8px;">'
        html += '<h3 style="color: #495057; margin-top: 0;">📍 DIRECCIÓN - Campos en la BD</h3>'
        
        if obj.encrypted_address:
            # Campo encrypted_address
            html += '<div style="margin-bottom: 15px;">'
            html += '<strong style="color: #856404;">Campo: encrypted_address</strong><br>'
            html += '<div style="background: #fff; padding: 10px; border: 1px solid #dee2e6; border-radius: 4px; margin-top: 5px;">'
            html += f'<code style="word-break: break-all; color: #212529;">{obj.encrypted_address}</code>'
            html += '</div>'
            html += f'<small style="color: #6c757d;">Tamaño: {len(obj.encrypted_address)} caracteres</small>'
            html += '</div>'
            
            # Campo address_key
            html += '<div style="margin-bottom: 15px;">'
            html += '<strong style="color: #0c5460;">Campo(AES): address_key</strong><br>'
            html += '<div style="background: #fff; padding: 10px; border: 1px solid #dee2e6; border-radius: 4px; margin-top: 5px;">'
            html += f'<code style="word-break: break-all; color: #212529;">{obj.address_key}</code>'
            html += '</div>'
            html += f'<small style="color: #6c757d;">Tamaño: {len(obj.address_key)} caracteres</small>'
            html += '</div>'
            
            # Campo address_iv
            html += '<div>'
            html += '<strong style="color: #004085;">Campo(RSA): address_iv</strong><br>'
            html += '<div style="background: #fff; padding: 10px; border: 1px solid #dee2e6; border-radius: 4px; margin-top: 5px;">'
            html += f'<code style="color: #212529;">{obj.address_iv}</code>'
            html += '</div>'
            html += f'<small style="color: #6c757d;">Tamaño: {len(obj.address_iv)} caracteres</small>'
            html += '</div>'
        else:
            html += '<p style="color: #dc3545;">❌ No hay datos cifrados</p>'
        
        html += '</div>'
        html += '</div>'
        
        return mark_safe(html)
    
    show_encrypted_data.short_description = '🔒 Datos Cifrados en BD'
    
    # ==================== ACCIONES ====================
    
    # REEMPLAZO COMPLETO DE LAS ACCIONES EN store/admin.py
# Busca la sección "ACCIONES" (aproximadamente línea 310) y reemplaza TODO hasta el final de CustomerAdmin

    # ==================== ACCIONES ====================
    
    actions = ['add_test_data_and_encrypt', 'verify_encryption']
    
    def add_test_data_and_encrypt(self, request, queryset):
        """Agrega datos de prueba y los cifra"""
        count = 0
        for customer in queryset:
            try:
                needs_update = False
                
                if not (customer.encrypted_phone and customer.phone_key and customer.phone_iv):
                    customer.phone = f"555-{customer.id:04d}-7890"
                    needs_update = True
                
                if not (customer.encrypted_address and customer.address_key and customer.address_iv):
                    customer.address = f"Calle Ejemplo #{customer.id}, Col. Centro, Ciudad Juárez, Chihuahua"
                    needs_update = True
                
                if needs_update:
                    customer.save()
                    count += 1
                    
            except Exception as e:
                logger.error(f"Error cifrando {customer.user.username}: {e}")
        
        if count > 0:
            self.message_user(request, f'✅ Se cifraron {count} customer(s). Abre uno para ver los datos.')
        else:
            self.message_user(request, '⚠️ Ya están cifrados.', level='WARNING')
    
    add_test_data_and_encrypt.short_description = '🔒 Cifrar datos (usa esto primero)'
    
    def verify_encryption(self, request, queryset):
        """Verifica que el cifrado y descifrado funcionen correctamente"""
        errors = 0
        verified = 0
        error_details = []
        
        for customer in queryset:
            try:
                # Verificar que existan datos cifrados
                has_phone = bool(customer.encrypted_phone and customer.phone_key and customer.phone_iv)
                has_address = bool(customer.encrypted_address and customer.address_key and customer.address_iv)
                
                if not has_phone and not has_address:
                    error_details.append(f"{customer.user.username}: No tiene datos cifrados")
                    errors += 1
                    continue
                
                # Intentar descifrar teléfono
                if has_phone:
                    try:
                        phone = customer.phone
                        logger.info(f"Teléfono descifrado para {customer.user.username}: {phone}")
                    except Exception as e:
                        error_details.append(f"{customer.user.username} - Teléfono: {str(e)[:50]}")
                        logger.error(f"Error descifrando teléfono de {customer.user.username}: {e}")
                        errors += 1
                        continue
                
                # Intentar descifrar dirección
                if has_address:
                    try:
                        address = customer.address
                        logger.info(f"Dirección descifrada para {customer.user.username}")
                    except Exception as e:
                        error_details.append(f"{customer.user.username} - Dirección: {str(e)[:50]}")
                        logger.error(f"Error descifrando dirección de {customer.user.username}: {e}")
                        errors += 1
                        continue
                
                verified += 1
                
            except Exception as e:
                errors += 1
                error_details.append(f"{customer.user.username}: {str(e)[:50]}")
                logger.error(f"Error verificando {customer.user.username}: {e}")
        
        # Mostrar resultados
        if errors == 0:
            self.message_user(request, f'✅ {verified} customer(s) verificados correctamente.')
        else:
            msg = f'⚠️ {verified} exitosos, {errors} errores. '
            if error_details:
                msg += 'Errores: ' + ' | '.join(error_details[:3])
            self.message_user(request, msg, level='WARNING')
    
    verify_encryption.short_description = '✅ Verificar cifrado'


# DESPUÉS DE ESTO, CONTINÚA CON LAS OTRAS CLASES (OrderItemInline, OrderAdmin, etc.)


class OrderItemInline(admin.TabularInline):
    model = OrderItem
    extra = 0

@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = ['id', 'customer', 'date_ordered', 'status', 'complete']
    list_filter = ['status', 'complete', 'date_ordered']
    search_fields = ['customer__user__username', 'transaction_id']
    inlines = [OrderItemInline]

@admin.register(OrderItem)
class OrderItemAdmin(admin.ModelAdmin):
    list_display = ['product', 'order', 'quantity', 'date_added']
    list_filter = ['date_added']
    search_fields = ['product__name', 'order__customer__user__username']