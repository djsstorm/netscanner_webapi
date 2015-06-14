from django.db import models

# Create your models here.

class Category(models.Model):
    id = models.IntegerField(unique=True,primary_key=True)
    name = models.CharField(max_length=128, unique=True)

    def save(self, *args, **kwargs):
        super(Category, self).save(*args, **kwargs)

    def __unicode__(self):  #For Python 2, use __str__ on Python 3
        return self.name

class Page(models.Model):
    category = models.ForeignKey(Category)
    title = models.CharField(max_length=128)
    url = models.URLField()
    views = models.IntegerField(default=0)

    def __unicode__(self):      #For Python 2, use __str__ on Python 3
        return self.title