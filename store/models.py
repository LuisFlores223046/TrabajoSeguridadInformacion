from django.db import models
from django.urls import reverse
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

class Category(models.Model):
    """Modelo para categorías de productos de café"""
    name = models.CharField(max_length=200, unique=True)  # Nombre único
    description = models.TextField(blank=True)  # Descripción opcional
    
    class Meta:
        verbose_name_plural = 'Categories'
        ordering = ['name']  # Orden alfabético
    
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
    description = models.TextField()
    price = models.DecimalField(max_digits=6, decimal_places=2)
    stock = models.IntegerField(default=0)
    image = models.ImageField(upload_to='products/', blank=True, null=True)
    roast_level = models.CharField(max_length=20, choices=ROAST_CHOICES)
    origin = models.CharField(max_length=100)  # País o región de origen
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


class Customer(models.Model):
    """Extensión del modelo User con información adicional"""
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone = models.CharField(max_length=15, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    
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
    except User.customer.RelatedObjectDoesNotExist:
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
    complete = models.BooleanField(default=False)  # Indica si el pedido está finalizado
    transaction_id = models.CharField(max_length=100, null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    shipping_address = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-date_ordered']  # Más recientes primero
    
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
    """Modelo para ítems individuales dentro de una orden"""
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    quantity = models.IntegerField(default=1)
    date_added = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f'{self.quantity} x {self.product.name}'
    
    @property
    def get_total(self):
        """Calcula el subtotal multiplicando precio por cantidad"""
        return self.product.price * self.quantity