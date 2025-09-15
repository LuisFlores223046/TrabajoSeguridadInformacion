from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
import bleach
import re
from .models import Product, Category, Customer, Order, OrderItem

def validate_image(image):
    """Validador personalizado para imágenes"""
    # Validar tamaño (máximo 5MB)
    if image.size > 5 * 1024 * 1024:
        raise ValidationError("Image file too large (max 5MB)")
    
    # Validar extensión
    allowed_extensions = ['.jpg', '.jpeg', '.png', '.gif']
    file_extension = image.name.lower().split('.')[-1]
    if f'.{file_extension}' not in allowed_extensions:
        raise ValidationError("Invalid image format. Only JPG, PNG and GIF are allowed.")
    
    return image

def clean_user_input(text):
    """Limpia entrada de usuario de HTML malicioso"""
    if text:
        # No permitir tags HTML
        return bleach.clean(text, tags=[], strip=True)
    return text

class CategoryForm(forms.ModelForm):
    """Formulario para crear y editar categorías"""
    class Meta:
        model = Category
        fields = ['name', 'description']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control', 'maxlength': 200}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'maxlength': 1000}),
        }
    
    def clean_name(self):
        """Validar y limpiar nombre de categoría"""
        name = self.cleaned_data.get('name')
        if name:
            cleaned_name = clean_user_input(name.strip())
            if len(cleaned_name) < 2:
                raise ValidationError("Category name must be at least 2 characters long.")
            return cleaned_name
        return name
    
    def clean_description(self):
        """Validar y limpiar descripción"""
        description = self.cleaned_data.get('description')
        if description:
            return clean_user_input(description.strip())
        return description

class ProductForm(forms.ModelForm):
    """Formulario para crear y editar productos"""
    class Meta:
        model = Product
        fields = ['name', 'category', 'description', 'price', 'stock', 'image', 
                 'roast_level', 'origin', 'format', 'weight', 'is_available']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control', 'maxlength': 200}),
            'category': forms.Select(attrs={'class': 'form-select'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'maxlength': 2000}),
            'price': forms.NumberInput(attrs={'class': 'form-control', 'min': '0.01', 'step': '0.01'}),
            'stock': forms.NumberInput(attrs={'class': 'form-control', 'min': '0'}),
            'roast_level': forms.Select(attrs={'class': 'form-select'}),
            'origin': forms.TextInput(attrs={'class': 'form-control', 'maxlength': 100}),
            'format': forms.Select(attrs={'class': 'form-select'}),
            'weight': forms.NumberInput(attrs={'class': 'form-control', 'min': '1'}),
            'is_available': forms.CheckboxInput(attrs={'class': 'form-check-input'})
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Añadir validador de imagen
        self.fields['image'].validators.append(validate_image)
    
    def clean_name(self):
        """Validar y limpiar nombre del producto"""
        name = self.cleaned_data.get('name')
        if name:
            cleaned_name = clean_user_input(name.strip())
            if len(cleaned_name) < 2:
                raise ValidationError("Product name must be at least 2 characters long.")
            return cleaned_name
        return name
    
    def clean_description(self):
        """Validar y limpiar descripción"""
        description = self.cleaned_data.get('description')
        if description:
            return clean_user_input(description.strip())
        return description
    
    def clean_origin(self):
        """Validar y limpiar origen"""
        origin = self.cleaned_data.get('origin')
        if origin:
            cleaned_origin = clean_user_input(origin.strip())
            # Validar que solo contenga letras, espacios y algunos caracteres especiales
            if not re.match(r'^[A-Za-z\s\-,\.]+$', cleaned_origin):
                raise ValidationError("Origin can only contain letters, spaces, hyphens, commas and periods.")
            return cleaned_origin
        return origin
    
    def clean_price(self):
        """Validar precio"""
        price = self.cleaned_data.get('price')
        if price is not None:
            if price <= 0:
                raise ValidationError("Price must be greater than 0.")
            if price > 999999.99:
                raise ValidationError("Price cannot exceed $999,999.99.")
        return price
    
    def clean_stock(self):
        """Validar stock"""
        stock = self.cleaned_data.get('stock')
        if stock is not None:
            if stock < 0:
                raise ValidationError("Stock cannot be negative.")
            if stock > 999999:
                raise ValidationError("Stock cannot exceed 999,999 units.")
        return stock
    
    def clean_weight(self):
        """Validar peso"""
        weight = self.cleaned_data.get('weight')
        if weight is not None:
            if weight <= 0:
                raise ValidationError("Weight must be greater than 0.")
            if weight > 10000:
                raise ValidationError("Weight cannot exceed 10,000 grams.")
        return weight

class LoginForm(AuthenticationForm):
    """Formulario de login con estilos Bootstrap y validación"""
    username = forms.CharField(
        widget=forms.TextInput(attrs={
            'class': 'form-control', 
            'placeholder': 'Username',
            'maxlength': 150
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control', 
            'placeholder': 'Password'
        })
    )
    
    def clean_username(self):
        """Limpiar username"""
        username = self.cleaned_data.get('username')
        if username:
            return clean_user_input(username.strip())
        return username

class RegistrationForm(UserCreationForm):
    """Formulario de registro con campos adicionales y validación mejorada"""
    first_name = forms.CharField(
        max_length=30, 
        required=True, 
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'pattern': r'[A-Za-z\s]+',
            'title': 'Only letters and spaces allowed'
        })
    )
    last_name = forms.CharField(
        max_length=30, 
        required=True, 
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'pattern': r'[A-Za-z\s]+',
            'title': 'Only letters and spaces allowed'
        })
    )
    email = forms.EmailField(
        max_length=254, 
        required=True, 
        widget=forms.EmailInput(attrs={'class': 'form-control'})
    )
    
    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'password1', 'password2')
        
    def __init__(self, *args, **kwargs):
        """Añade clases Bootstrap a los campos heredados"""
        super().__init__(*args, **kwargs)
        self.fields['username'].widget.attrs.update({'class': 'form-control', 'maxlength': 150})
        self.fields['password1'].widget.attrs.update({'class': 'form-control'})
        self.fields['password2'].widget.attrs.update({'class': 'form-control'})
    
    def clean_email(self):
        """Validar que el email sea único"""
        email = self.cleaned_data.get('email')
        if email:
            if User.objects.filter(email=email).exists():
                raise ValidationError("This email is already in use.")
        return email
    
    def clean_first_name(self):
        """Validar y limpiar nombre"""
        first_name = self.cleaned_data.get('first_name')
        if first_name:
            cleaned_name = clean_user_input(first_name.strip())
            if not cleaned_name.replace(' ', '').isalpha():
                raise ValidationError("First name can only contain letters and spaces.")
            return cleaned_name
        return first_name
    
    def clean_last_name(self):
        """Validar y limpiar apellido"""
        last_name = self.cleaned_data.get('last_name')
        if last_name:
            cleaned_name = clean_user_input(last_name.strip())
            if not cleaned_name.replace(' ', '').isalpha():
                raise ValidationError("Last name can only contain letters and spaces.")
            return cleaned_name
        return last_name
    
    def clean_username(self):
        """Validar y limpiar username"""
        username = self.cleaned_data.get('username')
        if username:
            cleaned_username = clean_user_input(username.strip())
            # Validar que solo contenga caracteres alfanuméricos y algunos especiales
            if not re.match(r'^[a-zA-Z0-9_@+.-]+$', cleaned_username):
                raise ValidationError("Username can only contain letters, numbers and @/./+/-/_ characters.")
            return cleaned_username
        return username

class ProfileUpdateForm(forms.ModelForm):
    """Formulario seguro para actualizar perfil de usuario"""
    
    # Campos adicionales para el modelo Customer
    phone = forms.CharField(
        max_length=15, 
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control', 
            'pattern': r'[\+]?[0-9\s\-\(\)]+',
            'title': 'Enter a valid phone number'
        })
    )
    address = forms.CharField(
        max_length=500,
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control', 
            'rows': 3,
            'maxlength': 500
        })
    )
    
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email']
        widgets = {
            'first_name': forms.TextInput(attrs={
                'class': 'form-control', 
                'maxlength': 30,
                'pattern': r'[A-Za-z\s]+',
                'title': 'Only letters and spaces allowed'
            }),
            'last_name': forms.TextInput(attrs={
                'class': 'form-control', 
                'maxlength': 30,
                'pattern': r'[A-Za-z\s]+',
                'title': 'Only letters and spaces allowed'
            }),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
        }
    
    def clean_email(self):
        """Validar que el email sea único"""
        email = self.cleaned_data.get('email')
        if email:
            if User.objects.filter(email=email).exclude(pk=self.instance.pk).exists():
                raise ValidationError("This email is already in use by another account.")
        return email
    
    def clean_first_name(self):
        """Validar y limpiar nombre"""
        first_name = self.cleaned_data.get('first_name')
        if first_name:
            cleaned_name = clean_user_input(first_name.strip())
            if not cleaned_name.replace(' ', '').isalpha():
                raise ValidationError("First name can only contain letters and spaces.")
            if len(cleaned_name) > 30:
                raise ValidationError("First name cannot exceed 30 characters.")
            return cleaned_name
        return first_name
    
    def clean_last_name(self):
        """Validar y limpiar apellido"""
        last_name = self.cleaned_data.get('last_name')
        if last_name:
            cleaned_name = clean_user_input(last_name.strip())
            if not cleaned_name.replace(' ', '').isalpha():
                raise ValidationError("Last name can only contain letters and spaces.")
            if len(cleaned_name) > 30:
                raise ValidationError("Last name cannot exceed 30 characters.")
            return cleaned_name
        return last_name
    
    def clean_phone(self):
        """Validar formato de teléfono"""
        phone = self.cleaned_data.get('phone')
        if phone:
            cleaned_phone = clean_user_input(phone.strip())
            if not re.match(r'^[\+]?[0-9\s\-\(\)]+$', cleaned_phone):
                raise ValidationError("Phone number contains invalid characters.")
            return cleaned_phone
        return phone
    
    def clean_address(self):
        """Validar y limpiar dirección"""
        address = self.cleaned_data.get('address')
        if address:
            cleaned_address = clean_user_input(address.strip())
            if len(cleaned_address) > 500:
                raise ValidationError("Address cannot exceed 500 characters.")
            return cleaned_address
        return address

class OrderForm(forms.ModelForm):
    """Formulario para actualizar órdenes"""
    class Meta:
        model = Order
        fields = ['status', 'shipping_address']
        widgets = {
            'status': forms.Select(attrs={'class': 'form-select'}),
            'shipping_address': forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'maxlength': 500}),
        }
    
    def clean_shipping_address(self):
        """Limpiar dirección de envío"""
        address = self.cleaned_data.get('shipping_address')
        if address:
            return clean_user_input(address.strip())
        return address

class OrderItemForm(forms.ModelForm):
    """Formulario para añadir/editar ítems de una orden"""
    class Meta:
        model = OrderItem
        fields = ['product', 'quantity']
        widgets = {
            'product': forms.Select(attrs={'class': 'form-select'}),
            'quantity': forms.NumberInput(attrs={'class': 'form-control', 'min': 1, 'max': 999}),
        }
    
    def clean_quantity(self):
        """Validar cantidad"""
        quantity = self.cleaned_data.get('quantity')
        if quantity is not None:
            if quantity <= 0:
                raise ValidationError("Quantity must be greater than 0.")
            if quantity > 999:
                raise ValidationError("Quantity cannot exceed 999.")
        return quantity