#!/usr/bin/env python
# coding: utf-8

# In[1]:


from pywebio.input import *
from pywebio.output import *
import sqlite3 as sql
from pywebio.output import *
from pywebio.pin import *
import hashlib 
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from Crypto.Random import get_random_bytes


# In[2]:


user_bd=sql.connect('sql_base_manass.bd')
with user_bd:
    cur = user_bd.cursor()    
    sql_command="CREATE TABLE IF NOT EXISTS `Passager` ('user' STRING, `domain` STRING, `password` STRING, 'hash' STRING)"
    cur.execute(sql_command)  
    sql_command="CREATE TABLE IF NOT EXISTS `users` (`user` STRING, `masterpass` STRING, `salt` STRING)"
    cur.execute(sql_command)  


# In[3]:


## прнимает string и hex 

def main_key_from_masterkey(masterkey,salt):
    byte_masterkey=masterkey.encode('utf-8')
    byte_salt=bytes.fromhex(salt)
    main_key=hashlib.pbkdf2_hmac('sha256', byte_masterkey, byte_salt, 100000).hex()
    return main_key

## возвращает hex


# In[4]:


def password_padder(password):
    bytes_password=password.encode('utf-8')
    padd_len=64-len(bytes_password)
    padded_password=bytes_password+padd_len*b'\x00'


# In[5]:


def decrypted_password_proc(decrypted_password):
    password_symb=decrypted_password[0]
    bytes_password=b''
    i=0
    for symb in decrypted_password:
        if(symb==b'\x00'):
            break
        bytes_password=bytes_password+symb
    return bytes_password.decode()


# In[6]:


def password_encrypter(password,k2):
    bytes_password=password.encode('utf-8')
    nonce=b'needednonce.'
    associated_data=b'why we even need this'
    cha=ChaCha20Poly1305(bytes.fromhex(k2))
    encrypted_password=cha.encrypt(nonce,bytes_password,associated_data)
    return encrypted_password.hex()


# In[7]:


def password_decrypter(password,k2):
    bytes_password=bytes.fromhex(password)
    nonce=b'needednonce.'
    associated_data=b'why we even need this'
    cha=ChaCha20Poly1305(bytes.fromhex(k2))
    try:
        decrypted_password=cha.decrypt(nonce,bytes_password,associated_data)
    except:
        return 'password was tampered'
    return decrypted_password.decode()


# In[8]:


def masterpass_hasher(masterpass):
    bytes_masterpass=masterpass.encode('utf-8')
    hash_masterpass=hashlib.sha256(bytes_masterpass).hexdigest()
    return hash_masterpass


# In[9]:


def cipher_keys_from_mainkey(mainkey):
    byte_mainkey=bytes.fromhex(mainkey)
    byte_vector1=byte_mainkey[0:10]
    byte_vector2=byte_mainkey[10:20]
    key1=hashlib.pbkdf2_hmac('sha256', byte_mainkey, byte_vector1, 100000).hex()
    key2=hashlib.pbkdf2_hmac('sha256', byte_mainkey, byte_vector2, 100000).hex()
    return key1,key2


# In[10]:


def hash_domain(domain,k1):
    domain_and_key_bytes_to_hash=domain.encode('utf-8')+bytes.fromhex(k1)
    hash_hex=hashlib.sha256(domain_and_key_bytes_to_hash).hexdigest()
    return hash_hex


# In[11]:


def hash_raw(domain_hash,password_hash,k1):
    raw_to_hash=bytes.fromhex(domain_hash+password_hash+k1)
    hash_hex=hashlib.sha256(raw_to_hash).hexdigest()
    return hash_hex


# In[12]:


def pass_adder(login, k1, k2, masterpass):
    with use_scope('Add_form'):
        with popup('Введите данные нового пароля'):
            put_input('domain_to_add', label='Введите имя ресурса').show()
            put_input('password_to_add', label='Введите пароль').show()
            print('aaaaaaa12a')
            put_buttons(['Добавить'], onclick=lambda _: raw_adder(pin.password_to_add, pin.domain_to_add,login,k1,k2,masterpass)).show()


# In[13]:


def raw_adder(password, domain, login, k1, k2, masterpass):

    domain_hash=hash_domain(domain,k1)
    print(domain_hash)
    password_encrypted=password_encrypter(password,k2)
    raw_hash=hash_raw(domain_hash,password_encrypted,k1)
    user_bd=sql.connect('sql_base_manass.bd')
    with user_bd:
        cur = user_bd.cursor()    
        sql_command="INSERT INTO 'Passager' VALUES (?,?,?,?)"
        cur.execute(sql_command, (login, domain_hash, password_encrypted, raw_hash)) 
    close_popup()
    clear('Add_form')
    main_page(login,masterpass)
    


# In[14]:


def auth_check(login,masterpass):
    masterpass_hash=masterpass_hasher(masterpass)
    user_bd=sql.connect('sql_base_manass.bd')
    with user_bd:
        cur = user_bd.cursor()    
        sql_command="SELECT * FROM users WHERE user=? and masterpass=?"
        cur.execute(sql_command, (login, masterpass_hash))
        if(cur.fetchall()==[]):
            with popup('Invaild input'):
                put_text("Incorrect login or masterpassword").show()
                auth()
        main_page(login,masterpass)
            
    


# In[15]:


def registration():
    clear()
    with use_scope('Registration'):
        put_input('login1', label='Введите логин').show()
        put_input('password1', label='Введите пароль').show()
        put_buttons(['Зарегестрироваться'], onclick=lambda _: reg_check(pin.login1,pin.password1)).show()


# In[24]:


def reg_check(login,password):
    user_bd=sql.connect('sql_base_manass.bd')
    with user_bd:
        cur=user_bd.cursor()
        sql_command="SELECT * FROM users WHERE user=?"
        cur.execute(sql_command,(login,))
        if cur.fetchall()!=[]:  
            with popup('Invaild input'):
                put_text("Login already taken").show()
                registration()
        else:
            password_hash=masterpass_hasher(password)
            salt=get_random_bytes(10).hex()
            sql_command="INSERT INTO users VALUES (?,?,?)"
            cur.execute(sql_command,(login,password_hash, salt))
            clear()
            auth()


# In[17]:


def auth():
    clear('logout')
    clear('Auth_form')
    clear('Reg_button')
    with use_scope('Auth_form'):
        put_input('login', label='Введите логин').show()
        put_input('password', label='Введите пароль').show()
        put_buttons(['Войти'], onclick=lambda _: auth_check(pin.login,pin.password)).show()
    with use_scope('Reg_button'):
        put_buttons(['Зарегестрироваться'], onclick=lambda _: registration()).show()


# In[18]:


def password_edit_form(encrypted_password,hashed_domain, login, k1, k2, masterpass):
    close_popup()
    with popup('Изменение пароля'):
        put_input('new_password', label='Введите новый пароль').show()
        put_buttons(['Изменить'], onclick=lambda _: password_edit(pin.new_password,hashed_domain, login, k1, k2, masterpass)).show()
        


# In[19]:


def password_edit(new_password,hashed_domain, login, k1, k2, masterpass):
    new_password_encrypted=password_encrypter(new_password, k2)
    user_bd=sql.connect('sql_base_manass.bd')
    with user_bd:
        cur=user_bd.cursor()
        sql_command="UPDATE 'Passager' SET password=? WHERE (user=? AND domain=?)"
        cur.execute(sql_command,(new_password_encrypted,login,hashed_domain))
    close_popup()
    main_page(login, masterpass)

    


# In[20]:


def password_delete(hashed_domain, login, k1, k2, masterpass):
    user_bd=sql.connect('sql_base_manass.bd')
    with user_bd:
        cur=user_bd.cursor()
        sql_command="DELETE FROM 'Passager' WHERE (user=? AND domain=?)"
        cur.execute(sql_command,(login,hashed_domain))
    close_popup()
    main_page(login, masterpass)


# In[21]:


def domain_search(domain, login, k1, k2, masterpass):
    hashed_domain=hash_domain(domain,k1)
    user_bd=sql.connect('sql_base_manass.bd')
    with user_bd:
        cur = user_bd.cursor()
        sql_command="SELECT password FROM Passager WHERE domain=? AND user=?"
        cur.execute(sql_command,(hashed_domain, login))
        try:
            encrypted_password=cur.fetchall()[0][0] 
            password=password_decrypter(encrypted_password, k2)
            with popup('Пароль для {domain}'.format(domain=domain)):
                put_text(password).show()
                put_buttons(['Изменить'], onclick=lambda _: password_edit_form(encrypted_password,hashed_domain, login, k1, k2, masterpass)).show()
                put_buttons(['Удалить'], onclick=lambda _: password_delete(hashed_domain, login, k1, k2, masterpass)).show()
        except:
            with popup('Ошибка поиска'):
                put_text("Пароля для данного домена нет в базе").show()
                main_page(login,masterpass)

    #main_page(login,masterpass)
        


# In[25]:


def main_page(login,masterpass):
    clear('logout')
    clear('Auth_form')
    clear('Reg_button')
    clear('Main_page')
    with use_scope('Main_page'):
        user_bd=sql.connect('sql_base_manass.bd')
        with user_bd:
            cur = user_bd.cursor()
            sql_command="SELECT salt FROM users WHERE user=?"
            cur.execute(sql_command,(login,))
            salt=cur.fetchall()[0][0]
            
        main_key=main_key_from_masterkey(masterpass,salt)
        k1,k2=cipher_keys_from_mainkey(main_key)
        with use_scope('Search_key_form'):
            put_input('searched_domain', label='Введите имя сервиса').show()
            put_buttons(['Поиск пароля'], onclick=lambda _: domain_search(pin.searched_domain, login, k1, k2, masterpass)).show()
            put_buttons(['Добавить пароль'], onclick=lambda _: pass_adder(login, k1, k2, masterpass)).show()
    with use_scope('logout'):
            put_buttons(['Выйти'], onclick=lambda _: auth()).show()


# In[23]:


auth()


# In[ ]:





# In[27]:


user_bd=sql.connect('sql_base_manass.bd')
with user_bd:
        cur = user_bd.cursor()
        sql_command="SELECT * FROM users "
        cur.execute(sql_command)
        res=cur.fetchall()
res


# In[28]:


user_bd=sql.connect('sql_base_manass.bd')
with user_bd:
        cur = user_bd.cursor()
        sql_command="SELECT * FROM Passager "
        cur.execute(sql_command)
        res=cur.fetchall()
res


# In[ ]:




