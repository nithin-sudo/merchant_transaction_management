from django.db import models

class Customer(models.Model):
    customer_id = models.AutoField(primary_key=True, auto_created=True)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    street = models.CharField(max_length=50)
    city = models.CharField(max_length=50)
    state = models.CharField(max_length=50)
    zip_code = models.CharField(max_length=10)
    phone = models.CharField(max_length=15)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'customer'

class Product(models.Model):
    product_id = models.AutoField(primary_key=True, auto_created=True)
    product_name = models.CharField(max_length=100)
    product_description = models.TextField(null=True, blank=True)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'product'

class User(models.Model):
    user_id = models.AutoField(primary_key=True, auto_created=True)
    username = models.CharField(max_length=50)
    password = models.CharField(max_length=255)
    role = models.CharField(max_length=15)
    email = models.EmailField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'user'

class Merchant(models.Model):
    merchant_id = models.AutoField(primary_key=True, auto_created=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    business_name = models.CharField(max_length=50)
    active = models.CharField(max_length=1, choices=[('Y', 'Yes'), ('N', 'No')])
    street = models.CharField(max_length=50)
    city = models.CharField(max_length=50)
    state = models.CharField(max_length=50)
    zip_code = models.CharField(max_length=10)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'merchant'

class Order(models.Model):
    order_id = models.AutoField(primary_key=True, auto_created=True)
    merchant = models.ForeignKey(Merchant, on_delete=models.CASCADE)
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE)
    order_reference = models.CharField(max_length=50)
    order_amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=20)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'order'

class OrderDetail(models.Model):
    order_detail_id = models.AutoField(primary_key=True, auto_created=True)
    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.IntegerField()
    price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    refund = models.CharField(max_length=1, choices=[('Y', 'Yes'), ('N', 'No')])
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'orderdetail'
