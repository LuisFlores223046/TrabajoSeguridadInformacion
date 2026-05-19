import logging

from django.contrib import admin
from django.utils.html import format_html
from django.utils.safestring import mark_safe

from .models import Category, Product, Customer, Order, OrderItem

logger = logging.getLogger(__name__)


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'description']
    search_fields = ['name']


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ['name', 'category', 'price', 'stock', 'is_available', 'roast_level', 'format']
    list_filter = ['category', 'roast_level', 'format', 'is_available']
    search_fields = ['name', 'description', 'origin']
    list_editable = ['price', 'stock', 'is_available']


class EncryptionStatusFilter(admin.SimpleListFilter):
    title = 'Estado de Cifrado'
    parameter_name = 'encryption_status'

    def lookups(self, request, model_admin):
        return (
            ('encrypted', 'Cifrados'),
            ('not_encrypted', 'Sin cifrar'),
        )

    def queryset(self, request, queryset):
        if self.value() == 'encrypted':
            return queryset.exclude(encrypted_phone__isnull=True)
        if self.value() == 'not_encrypted':
            return queryset.filter(encrypted_phone__isnull=True)
        return queryset


@admin.register(Customer)
class CustomerAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'phone_status', 'address_status']
    list_filter = [EncryptionStatusFilter, 'user__is_active']
    search_fields = ['user__username', 'user__email']
    readonly_fields = ['user', 'show_encrypted_data']
    fieldsets = (
        ('Usuario', {'fields': ('user',)}),
        ('Detalles del Cifrado', {
            'fields': ('show_encrypted_data',),
            'classes': ('collapse',),
            'description': 'Expande para ver los datos técnicos de cómo se almacenan cifrados en la BD.',
        }),
    )
    actions = ['add_test_data_and_encrypt', 'verify_encryption']

    def _status_badge(self, is_encrypted: bool) -> str:
        if is_encrypted:
            return format_html(
                '<span style="background:#28a745;color:white;padding:4px 10px;border-radius:4px;font-size:12px;">CIFRADO</span>'
            )
        return format_html(
            '<span style="background:#dc3545;color:white;padding:4px 10px;border-radius:4px;font-size:12px;">NO</span>'
        )

    def phone_status(self, obj):
        return self._status_badge(bool(obj.encrypted_phone and obj.phone_key and obj.phone_iv))
    phone_status.short_description = 'Teléfono'

    def address_status(self, obj):
        return self._status_badge(bool(obj.encrypted_address and obj.address_key and obj.address_iv))
    address_status.short_description = 'Dirección'

    def show_encrypted_data(self, obj):
        def _field_block(label, value):
            if not value:
                return ''
            return (
                f'<div style="margin-bottom:12px;">'
                f'<strong style="color:#495057;">{label}</strong><br>'
                f'<code style="word-break:break-all;background:#fff;display:block;padding:8px;border:1px solid #dee2e6;border-radius:4px;margin-top:4px;">{value}</code>'
                f'<small style="color:#6c757d;">Tamaño: {len(value)} chars</small>'
                f'</div>'
            )

        html = '<div style="font-family:monospace;font-size:12px;">'

        # Teléfono
        html += '<div style="background:#f8f9fa;padding:16px;border-radius:8px;margin-bottom:16px;">'
        html += '<h4 style="margin-top:0;">Teléfono — campos en BD</h4>'
        if obj.encrypted_phone:
            html += _field_block('encrypted_phone (AES)', obj.encrypted_phone)
            html += _field_block('phone_key (RSA)', obj.phone_key)
            html += _field_block('phone_iv', obj.phone_iv)
        else:
            html += '<p style="color:#dc3545;">Sin datos cifrados.</p>'
        html += '</div>'

        # Dirección
        html += '<div style="background:#f8f9fa;padding:16px;border-radius:8px;">'
        html += '<h4 style="margin-top:0;">Dirección — campos en BD</h4>'
        if obj.encrypted_address:
            html += _field_block('encrypted_address (AES)', obj.encrypted_address)
            html += _field_block('address_key (RSA)', obj.address_key)
            html += _field_block('address_iv', obj.address_iv)
        else:
            html += '<p style="color:#dc3545;">Sin datos cifrados.</p>'
        html += '</div></div>'

        return mark_safe(html)
    show_encrypted_data.short_description = 'Datos Cifrados en BD'

    def add_test_data_and_encrypt(self, request, queryset):
        count = 0
        for customer in queryset:
            try:
                changed = False
                if not (customer.encrypted_phone and customer.phone_key and customer.phone_iv):
                    customer.phone = f'555{customer.id:07d}'
                    changed = True
                if not (customer.encrypted_address and customer.address_key and customer.address_iv):
                    customer.address = f'Calle Ejemplo #{customer.id}, Col. Centro, Ciudad Juárez, Chih.'
                    changed = True
                if changed:
                    customer.save()
                    count += 1
            except Exception as e:
                logger.error('Error cifrando datos de %s: %s', customer.user.username, e)
        if count:
            self.message_user(request, f'{count} cliente(s) cifrado(s) correctamente.')
        else:
            self.message_user(request, 'Los clientes seleccionados ya tenían datos cifrados.', level='WARNING')
    add_test_data_and_encrypt.short_description = 'Cifrar datos de prueba'

    def verify_encryption(self, request, queryset):
        ok = 0
        errors = []
        for customer in queryset:
            try:
                has_phone = bool(customer.encrypted_phone)
                has_address = bool(customer.encrypted_address)
                if not has_phone and not has_address:
                    errors.append(f'{customer.user.username}: sin datos cifrados')
                    continue
                if has_phone:
                    _ = customer.phone
                if has_address:
                    _ = customer.address
                ok += 1
            except Exception as e:
                errors.append(f'{customer.user.username}: {str(e)[:60]}')
                logger.error('Error verificando cifrado de %s: %s', customer.user.username, e)

        if not errors:
            self.message_user(request, f'{ok} cliente(s) verificado(s) correctamente.')
        else:
            msg = f'{ok} exitosos, {len(errors)} con errores. ' + ' | '.join(errors[:3])
            self.message_user(request, msg, level='WARNING')
    verify_encryption.short_description = 'Verificar cifrado'


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
