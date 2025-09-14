# store/models.py
from django.db import models
from django.urls import reverse
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator, MaxValueValidator, RegexValidator
from .validators import alphanumeric_validator, phone_validator
from django.db.models.signals import post_save, post_delete
import html


@receiver(post_save, sender=Product)
def log_product_changes(sender, instance, created, **kwargs):
    action = 'CREATED' if created else 'UPDATED'
    security_logger.info(f"PRODUCT_{action}: {instance.name} by system")

def validate_image_file(value):
    """Validador personalizado para archivos de imagen"""
    if not value:
        return
    
    # Verificar tamaño del archivo (máximo 5MB)
    if value.size > 5 * 1024 * 1024:
        raise ValidationError("Image file size cannot exceed 5MB.")
    
    # Verificar tipo de archivo
    allowed_types = ['image/jpeg', 'image/png', 'image/gif', 'image/webp']
    if hasattr(value, 'content_type') and value.content_type not in allowed_types:
        raise ValidationError("Only JPEG, PNG, GIF, and WebP images are allowed.")

def validate_positive_decimal(value):
    """Validador para números decimales positivos"""
    if value is not None and value < 0:
        raise ValidationError("Value must be positive.")

class Category(models.Model):
    """Modelo para categorías de productos de café con validaciones"""
    name = models.CharField(
        max_length=200, 
        unique=True,
        validators=[alphanumeric_validator],
        help_text="Category name (letters, numbers, spaces, hyphens only)"
    )
    description = models.TextField(
        blank=True,
        max_length=1000,
        help_text="Category description (max 1000 characters)"
    )
    
    class Meta:
        verbose_name_plural = 'Categories'
        ordering = ['name']
    
    def clean(self):
        """Validación personalizada del modelo"""
        super().clean()
        
        if self.name:
            # Normalizar y escapar el nombre
            self.name = html.escape(self.name.strip())
            
            # Verificar longitud
            if len(self.name) < 2:
                raise ValidationError({'name': 'Category name must be at least 2 characters long.'})
        
        if self.description:
            # Normalizar descripción
            self.description = html.escape(self.description.strip())
    
    def save(self, *args, **kwargs):
        """Sobrescribir save para ejecutar clean()"""
        self.clean()
        super().save(*args, **kwargs)
    
    def __str__(self):
        return self.name
    
    def get_absolute_url(self):
        """URL para ver detalles de la categoría"""
        return reverse('category_detail', args=[str(self.id)])

class Product(models.Model):
    """Modelo para productos de café con validaciones de seguridad"""
    
    # Opciones de tostado
    ROAST_CHOICES = [
        ('light', 'Light Roast'),
        ('medium', 'Medium Roast'),
        ('dark', 'Dark Roast'),
        ('espresso', 'Espresso Roast'),
    ]
    
    # Opciones de formato
    FORMAT_CHOICES = [
        ('whole_bean', 'Whole Bean'),
        ('ground', 'Ground'),
        ('capsule', 'Capsules'),
    ]
    
    name = models.CharField(
        max_length=200,
        validators=[alphanumeric_validator],
        help_text="Product name (max 200 characters)"
    )
    category = models.ForeignKey(
        Category, 
        on_delete=models.CASCADE, 
        related_name='products'
    )
    description = models.TextField(
        max_length=1000,
        help_text="Product description (max 1000 characters)"
    )
    price = models.DecimalField(
        max_digits=8, 
        decimal_places=2,
        validators=[
            MinValueValidator(0.01, message="Price must be greater than 0"),
            MaxValueValidator(999999.99, message="Price cannot exceed $999,999.99")
        ]
    )
    stock = models.IntegerField(
        default=0,
        validators=[
            MinValueValidator(0, message="Stock cannot be negative"),
            MaxValueValidator(999999, message="Stock cannot exceed 999,999")
        ]
    )
    image = models.ImageField(
        upload_to='products/', 
        blank=True, 
        null=True,
        validators=[validate_image_file],
        help_text="Product image (max 5MB, JPEG/PNG/GIF/WebP only)"
    )
    roast_level = models.CharField(
        max_length=20, 
        choices=ROAST_CHOICES,
        help_text="Coffee roast level"
    )
    origin = models.CharField(
        max_length=100,
        validators=[alphanumeric_validator],
        help_text="Country or region of origin"
    )
    format = models.CharField(
        max_length=20, 
        choices=FORMAT_CHOICES,
        help_text="Product format"
    )
    weight = models.IntegerField(
        validators=[
            MinValueValidator(1, message="Weight must be at least 1 gram"),
            MaxValueValidator(99999, message="Weight cannot exceed 99,999 grams")
        ],
        help_text="Weight in grams"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_available = models.BooleanField(
        default=True,
        help_text="Whether the product is available for purchase"
    )
    
    class Meta:
        ordering = ['name']
        indexes = [
            models.Index(fields=['name']),
            models.Index(fields=['category', 'is_available']),
            models.Index(fields=['created_at']),
        ]
    
    def clean(self):
        """Validación personalizada del modelo"""
        super().clean()
        
        if self.name:
            # Normalizar y escapar el nombre
            self.name = html.escape(self.name.strip())
            
            if len(self.name) < 2:
                raise ValidationError({'name': 'Product name must be at least 2 characters long.'})
        
        if self.description:
            # Normalizar descripción
            self.description = html.escape(self.description.strip())
        
        if self.origin:
            # Normalizar origen
            self.origin = html.escape(self.origin.strip())
        
        # Validación de lógica de negocio
        if self.stock == 0 and self.is_available:
            self.is_available = False
        
        if self.price and self.price <= 0:
            raise ValidationError({'price': 'Price must be greater than 0.'})
    
    def save(self, *args, **kwargs):
        """Sobrescribir save para ejecutar clean()"""
        self.clean()
        super().save(*args, **kwargs)
    
    def __str__(self):
        return self.name
    
    def get_absolute_url(self):
        """URL para ver detalles del producto"""
        return reverse('product_detail', args=[str(self.id)])

class Customer(models.Model):
    """Extensión del modelo User con validaciones"""
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone = models.CharField(
        max_length=20, 
        blank=True, 
        null=True,
        validators=[phone_validator],
        help_text="Phone number (numbers, spaces, +, -, (, ) only)"
    )
    address = models.TextField(
        blank=True, 
        null=True,
        max_length=500,
        help_text="Address (max 500 characters)"
    )
    
    def clean(self):
        """Validación personalizada"""
        super().clean()
        
        if self.phone:
            # Normalizar teléfono
            import re
            self.phone = re.sub(r'[^\d\+\-\(\)\s]', '', self.phone.strip())
        
        if self.address:
            # Normalizar y escapar dirección
            self.address = html.escape(self.address.strip())
    
    def save(self, *args, **kwargs):
        """Sobrescribir save para ejecutar clean()"""
        self.clean()
        super().save(*args, **kwargs)
    
    def __str__(self):
        return self.user.username

# Signals para manejo automático de Customer
@receiver(post_save, sender=User)
def create_customer(sender, instance, created, **kwargs):
    """Crea un Customer cuando se crea un User"""
    if created:
        Customer.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_customer(sender, instance, **kwargs):
    """Actualiza el Customer cuando se actualiza un User"""
    try:
        instance.customer.save()
    except Customer.DoesNotExist:
        Customer.objects.create(user=instance)

class Order(models.Model):
    """Modelo para órdenes de compra con validaciones"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('shipped', 'Shipped'),
        ('delivered', 'Delivered'),
        ('cancelled', 'Cancelled'),
    ]
    
    customer = models.ForeignKey(
        Customer, 
        on_delete=models.CASCADE, 
        related_name='orders'
    )
    date_ordered = models.DateTimeField(auto_now_add=True)
    complete = models.BooleanField(default=False)
    transaction_id = models.CharField(
        max_length=100, 
        null=True, 
        blank=True,
        validators=[RegexValidator(
            regex=r'^[A-Za-z0-9\-_]+$',
            message='Transaction ID can only contain letters, numbers, hyphens and underscores'
        )]
    )
    status = models.CharField(
        max_length=20, 
        choices=STATUS_CHOICES, 
        default='pending'
    )
    shipping_address = models.TextField(
        blank=True, 
        null=True,
        max_length=500,
        help_text="Shipping address (max 500 characters)"
    )
    
    class Meta:
        ordering = ['-date_ordered']
        indexes = [
            models.Index(fields=['customer', 'complete']),
            models.Index(fields=['date_ordered']),
            models.Index(fields=['status']),
        ]
    
    def clean(self):
        """Validación personalizada"""
        super().clean()
        
        if self.shipping_address:
            # Normalizar y escapar dirección
            self.shipping_address = html.escape(self.shipping_address.strip())
        
        if self.transaction_id:
            # Normalizar transaction ID
            self.transaction_id = self.transaction_id.strip()
    
    def save(self, *args, **kwargs):
        """Sobrescribir save para ejecutar clean()"""
        self.clean()
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f'Order {self.id} - {self.customer.user.username}'
    
    @property
    def get_cart_total(self):
        """Calcula el total del carrito sumando todos los ítems"""
        orderitems = self.orderitem_set.all()
        total = sum([item.get_total for item in orderitems])
        return total
    
    @property
    def get_cart_items(self):
        """Calcula el número total de ítems en el carrito"""
        orderitems = self.orderitem_set.all()
        total = sum([item.quantity for item in orderitems])
        return total

class OrderItem(models.Model):
    """Modelo para ítems individuales dentro de una orden con validaciones"""
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    quantity = models.IntegerField(
        default=1,
        validators=[
            MinValueValidator(1, message="Quantity must be at least 1"),
            MaxValueValidator(999, message="Quantity cannot exceed 999")
        ]
    )
    date_added = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['order', 'product']),
            models.Index(fields=['date_added']),
        ]
        # Evitar duplicados del mismo producto en la misma orden
        unique_together = ['order', 'product']
    
    def clean(self):
        """Validación personalizada"""
        super().clean()
        
        # Validar que el producto esté disponible
        if self.product and not self.product.is_available:
            raise ValidationError({'product': 'Selected product is not available.'})
        
        # Validar que hay suficiente stock
        if self.product and self.quantity > self.product.stock:
            raise ValidationError({
                'quantity': f'Only {self.product.stock} units available for {self.product.name}.'
            })
    
    def save(self, *args, **kwargs):
        """Sobrescribir save para ejecutar clean()"""
        self.clean()
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f'{self.quantity} x {self.product.name}'
    
    @property
    def get_total(self):
        """Calcula el subtotal multiplicando precio por cantidad"""
        return self.product.price * self.quantity