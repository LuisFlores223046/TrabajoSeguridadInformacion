import os
import re
import logging

from django.db import models
from django.urls import reverse
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.exceptions import ValidationError

logger = logging.getLogger(__name__)


def validate_image(image):
    if image.size > 5 * 1024 * 1024:
        raise ValidationError('La imagen no puede superar 5 MB.')
    ext = os.path.splitext(image.name)[1].lower()
    if ext not in ('.jpg', '.jpeg', '.png', '.gif'):
        raise ValidationError('Formato no válido. Usa JPG, PNG o GIF.')
    return image


def product_image_path(instance, filename):
    clean = re.sub(r'[^\w\-_\.]', '', filename)
    return f'products/{clean}'


class Category(models.Model):
    name = models.CharField(max_length=200, unique=True)
    description = models.TextField(blank=True, max_length=1000)

    class Meta:
        verbose_name_plural = 'Categories'
        ordering = ['name']

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse('category_detail', args=[self.id])


class Product(models.Model):
    ROAST_CHOICES = [
        ('light', 'Light Roast'),
        ('medium', 'Medium Roast'),
        ('dark', 'Dark Roast'),
        ('espresso', 'Espresso Roast'),
    ]
    FORMAT_CHOICES = [
        ('whole_bean', 'Whole Bean'),
        ('ground', 'Ground'),
        ('capsule', 'Capsules'),
    ]

    name = models.CharField(max_length=200)
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name='products')
    description = models.TextField(max_length=2000)
    price = models.DecimalField(max_digits=8, decimal_places=2)
    stock = models.IntegerField(default=0)
    image = models.ImageField(
        upload_to=product_image_path,
        blank=True,
        null=True,
        validators=[validate_image],
        help_text='Máximo 5 MB. Formatos: JPG, PNG, GIF.',
    )
    roast_level = models.CharField(max_length=20, choices=ROAST_CHOICES)
    origin = models.CharField(max_length=100)
    format = models.CharField(max_length=20, choices=FORMAT_CHOICES)
    weight = models.IntegerField(help_text='Peso en gramos')
    is_available = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse('product_detail', args=[self.id])

    def clean(self):
        super().clean()
        if self.price is not None and self.price <= 0:
            raise ValidationError({'price': 'El precio debe ser mayor que 0.'})
        if self.stock is not None and self.stock < 0:
            raise ValidationError({'stock': 'El stock no puede ser negativo.'})
        if self.weight is not None and self.weight <= 0:
            raise ValidationError({'weight': 'El peso debe ser mayor que 0.'})
        if self.stock == 0:
            self.is_available = False


class Customer(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)

    # Campos cifrados — teléfono
    encrypted_phone = models.TextField(blank=True, null=True)
    phone_key = models.TextField(blank=True, null=True)
    phone_iv = models.TextField(blank=True, null=True)

    # Campos cifrados — dirección
    encrypted_address = models.TextField(blank=True, null=True)
    address_key = models.TextField(blank=True, null=True)
    address_iv = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.user.username

    @property
    def phone(self):
        if self.encrypted_phone and self.phone_key and self.phone_iv:
            try:
                from .encryption import decrypt_sensitive_data
                return decrypt_sensitive_data({
                    'encrypted_data': self.encrypted_phone,
                    'encrypted_key': self.phone_key,
                    'iv': self.phone_iv,
                })
            except Exception as e:
                logger.error('Error descifrando teléfono de %s: %s', self.user.username, e)
                return ''
        return ''

    @phone.setter
    def phone(self, value):
        if value and value.strip():
            try:
                from .encryption import encrypt_sensitive_data
                result = encrypt_sensitive_data(value.strip())
                self.encrypted_phone = result['encrypted_data']
                self.phone_key = result['encrypted_key']
                self.phone_iv = result['iv']
            except Exception as e:
                logger.error('Error cifrando teléfono de %s: %s', self.user.username, e)
                raise
        else:
            self.encrypted_phone = None
            self.phone_key = None
            self.phone_iv = None

    @property
    def address(self):
        if self.encrypted_address and self.address_key and self.address_iv:
            try:
                from .encryption import decrypt_sensitive_data
                return decrypt_sensitive_data({
                    'encrypted_data': self.encrypted_address,
                    'encrypted_key': self.address_key,
                    'iv': self.address_iv,
                })
            except Exception as e:
                logger.error('Error descifrando dirección de %s: %s', self.user.username, e)
                return ''
        return ''

    @address.setter
    def address(self, value):
        if value and value.strip():
            try:
                from .encryption import encrypt_sensitive_data
                result = encrypt_sensitive_data(value.strip())
                self.encrypted_address = result['encrypted_data']
                self.address_key = result['encrypted_key']
                self.address_iv = result['iv']
            except Exception as e:
                logger.error('Error cifrando dirección de %s: %s', self.user.username, e)
                raise
        else:
            self.encrypted_address = None
            self.address_key = None
            self.address_iv = None


@receiver(post_save, sender=User)
def create_or_save_customer(sender, instance, created, **kwargs):
    if created:
        Customer.objects.create(user=instance)
    else:
        try:
            instance.customer.save()
        except Customer.DoesNotExist:
            Customer.objects.create(user=instance)


class Order(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('shipped', 'Shipped'),
        ('delivered', 'Delivered'),
        ('cancelled', 'Cancelled'),
    ]

    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name='orders')
    date_ordered = models.DateTimeField(auto_now_add=True)
    complete = models.BooleanField(default=False)
    transaction_id = models.CharField(max_length=100, null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    shipping_address = models.TextField(blank=True, null=True, max_length=500)

    class Meta:
        ordering = ['-date_ordered']

    def __str__(self):
        return f'Order {self.id} — {self.customer.user.username}'

    @property
    def get_cart_total(self):
        return sum(item.get_total for item in self.orderitem_set.all())

    @property
    def get_cart_items(self):
        return sum(item.quantity for item in self.orderitem_set.all())

    def clean(self):
        super().clean()
        if self.transaction_id:
            qs = Order.objects.filter(transaction_id=self.transaction_id)
            if self.pk:
                qs = qs.exclude(pk=self.pk)
            if qs.exists():
                raise ValidationError({'transaction_id': 'El ID de transacción debe ser único.'})


class OrderItem(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    quantity = models.IntegerField(default=1)
    date_added = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ['product', 'order']

    def __str__(self):
        return f'{self.quantity} × {self.product.name}'

    @property
    def get_total(self):
        return self.product.price * self.quantity

    def clean(self):
        super().clean()
        if self.quantity is not None and self.quantity <= 0:
            raise ValidationError({'quantity': 'La cantidad debe ser mayor que 0.'})
        if self.quantity is not None and self.quantity > 999:
            raise ValidationError({'quantity': 'La cantidad no puede superar 999.'})
        if self.product and not self.product.is_available:
            raise ValidationError({'product': 'El producto seleccionado no está disponible.'})
