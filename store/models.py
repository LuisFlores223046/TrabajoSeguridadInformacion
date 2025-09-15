from django.db import models
from django.urls import reverse
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.exceptions import ValidationError
import os

def validate_image(image):
    """Validador personalizado para imágenes de productos"""
    # Validar tamaño del archivo (máximo 5MB)
    if image.size > 5 * 1024 * 1024:
        raise ValidationError("Image file too large (max 5MB)")
    
    # Validar extensión del archivo
    allowed_extensions = ['.jpg', '.jpeg', '.png', '.gif']
    file_extension = os.path.splitext(image.name)[1].lower()
    if file_extension not in allowed_extensions:
        raise ValidationError("Invalid image format. Only JPG, PNG and GIF are allowed.")
    
    return image

def product_image_path(instance, filename):
    """Función para definir la ruta de subida de imágenes de productos"""
    # Limpiar el nombre del archivo
    import re
    clean_filename = re.sub(r'[^\w\-_\.]', '', filename)
    return f'products/{clean_filename}'

class Category(models.Model):
    """Modelo para categorías de productos de café"""
    name = models.CharField(max_length=200, unique=True)
    description = models.TextField(blank=True, max_length=1000)
    
    class Meta:
        verbose_name_plural = 'Categories'
        ordering = ['name']
    
    def __str__(self):
        return self.name
    
    def get_absolute_url(self):
        """URL para ver detalles de la categoría"""
        return reverse('category_detail', args=[str(self.id)])

class Product(models.Model):
    """Modelo para productos de café con detalles específicos"""
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
        help_text="Upload product image (max 5MB, JPG/PNG/GIF only)"
    )
    roast_level = models.CharField(max_length=20, choices=ROAST_CHOICES)
    origin = models.CharField(max_length=100)
    format = models.CharField(max_length=20, choices=FORMAT_CHOICES)
    weight = models.IntegerField(help_text="Weight in grams")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_available = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['name']
    
    def __str__(self):
        return self.name
    
    def get_absolute_url(self):
        """URL para ver detalles del producto"""
        return reverse('product_detail', args=[str(self.id)])
    
    def clean(self):
        """Validación personalizada del modelo"""
        super().clean()
        
        # Validar que el precio sea positivo
        if self.price is not None and self.price <= 0:
            raise ValidationError({'price': 'Price must be greater than 0.'})
        
        # Validar que el stock no sea negativo
        if self.stock is not None and self.stock < 0:
            raise ValidationError({'stock': 'Stock cannot be negative.'})
        
        # Validar que el peso sea positivo
        if self.weight is not None and self.weight <= 0:
            raise ValidationError({'weight': 'Weight must be greater than 0.'})
        
        # Si no hay stock, marcar como no disponible
        if self.stock == 0:
            self.is_available = False

class Customer(models.Model):
    """Extensión del modelo User con información adicional"""
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone = models.CharField(max_length=15, blank=True, null=True)
    address = models.TextField(blank=True, null=True, max_length=500)
    
    def __str__(self):
        return self.user.username
    
    def clean(self):
        """Validación personalizada del modelo Customer"""
        super().clean()
        
        # Validar formato de teléfono si se proporciona
        if self.phone:
            import re
            if not re.match(r'^[\+]?[0-9\s\-\(\)]+$', self.phone):
                raise ValidationError({'phone': 'Invalid phone number format.'})

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
    """Modelo para órdenes de compra"""
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
    
    def clean(self):
        """Validación personalizada del modelo Order"""
        super().clean()
        
        # Validar que el ID de transacción sea único si se proporciona
        if self.transaction_id:
            existing_orders = Order.objects.filter(transaction_id=self.transaction_id)
            if self.pk:
                existing_orders = existing_orders.exclude(pk=self.pk)
            if existing_orders.exists():
                raise ValidationError({'transaction_id': 'Transaction ID must be unique.'})

class OrderItem(models.Model):
    """Modelo para ítems individuales dentro de una orden"""
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    quantity = models.IntegerField(default=1)
    date_added = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        # Evitar duplicados del mismo producto en la misma orden
        unique_together = ['product', 'order']
    
    def __str__(self):
        return f'{self.quantity} x {self.product.name}'
    
    @property
    def get_total(self):
        """Calcula el subtotal multiplicando precio por cantidad"""
        return self.product.price * self.quantity
    
    def clean(self):
        """Validación personalizada del modelo OrderItem"""
        super().clean()
        
        # Validar que la cantidad sea positiva
        if self.quantity is not None and self.quantity <= 0:
            raise ValidationError({'quantity': 'Quantity must be greater than 0.'})
        
        # Validar que no exceda 999 unidades (límite razonable)
        if self.quantity is not None and self.quantity > 999:
            raise ValidationError({'quantity': 'Quantity cannot exceed 999.'})
        
        # Validar disponibilidad del producto
        if self.product and not self.product.is_available:
            raise ValidationError({'product': 'Selected product is not available.'})
        
        # Validar stock suficiente (solo para órdenes completadas)
        if (self.product and self.order and self.order.complete and 
            self.order.status != 'cancelled' and self.quantity > self.product.stock):
            raise ValidationError({
                'quantity': f'Not enough stock. Available: {self.product.stock}'
            })