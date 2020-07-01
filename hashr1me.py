import hashlib
from colored import fg, attr
import random

color1 = fg('green')
color2 = fg('red')
res = attr('reset')

print("Welcome to the Hashcracker - Made by r1me")
keuze = input("Do you want to generate or brute force a hash ? g / b : ")
while keuze == "g" or keuze == "b" or keuze == "e":

	if keuze == "g":

		print("""
	1) Generate MD5-hash
	2) Generate SHA1-hash
	3) Generate SHA256-hash
	0) Exit
		""")

		choice = input("Make a choice : ")
		if (choice == "1"):
			password = input("Input the password to hash : ")
			print()

			for i in range(1):
				passwd = bytes(password, 'utf-8')
				hash_object = hashlib.md5(passwd)
				guess_pw = hash_object.hexdigest()
				print("MD5 : " + guess_pw)
				print()
			yesorno = input("Do you want to use Hashcracker again ? (y/n) : ")
			if (yesorno == "y"):
				print("Welcome to the Hashcracker - Made by r1me")
				keuze = input("Do you want to generate or brute force a hash ? (g / b ) : ")
			else:
				print("Exiting...")
				break

		elif (choice == "2"):
			password = input("Input the password to hash : ")
			print()

			for i in range(1):
				passwd = bytes(password, 'utf-8')
				hash_object = hashlib.sha1(passwd)
				guess_pw = hash_object.hexdigest()
				print("SHA1 : " + guess_pw)
				print()
			yesorno = input("Do you want to use Hashcracker again ? (y/n) : ")
			if (yesorno == "y"):
				print("Welcome to the Hashcracker - Made by r1me")
				keuze = input("Do you want to generate or brute force a hash ? (g / b ) : ")
			else:
				print("Exiting...")
				break

		elif (choice == "3"):
			password = input("Input the password to hash : ")
			print()

			for i in range(1):
				passwd = bytes(password, 'utf-8')
				hash_object = hashlib.sha256(passwd)
				guess_pw = hash_object.hexdigest()
				print("SHA256 : " + guess_pw)
				print()
			yesorno = input("Do you want to use Hashcracker again ? (y/n) : ")
			if (yesorno == "y"):
				print("Welcome to the Hashcracker - Made by r1me")
				keuze = input("Do you want to generate or brute force a hash ? (g / b ) : ")
			else:
				print("Exiting...")
				break
		elif (choice == "0"):
			print("Exiting...")
			break

		else:
			print("You made a fault choice ")

	elif keuze == "b":
		print("""
	1) Brute force MD5-hash
	2) Brute force SHA1-hash
	3) Brute force SHA256-hash
	0) Exit	
		""")

		choice = input("Make a choice : ")

		if (choice == "1"):

			flag = 0
			pass_hash = input("Enter MD5 hash: ")
			
			rockyou = input("Do you want to use default wordlist [rockyou.txt] y/n : ")
			rockyou1 = "rockyou.txt"
			if (rockyou == "y"):
				try:
					passFile = open(rockyou1, "r", errors='ignore')
				except:
					print("No file found")
					quit()

				for word in passFile:

					enc_word = word.encode('utf-8')
					digest = hashlib.md5(enc_word.strip()).hexdigest()

					if digest == pass_hash:
						print(color1 + "Password found" + res)
						print("Password is --> " + word)
						flag = 1
						break

				if flag == 0:

					print(color2 + "Password is not in the list" + res)

				yesorno = input("Do you want to use Hashcracker again ? (y/n) : ")
				print()
				if (yesorno == "y"):
					print("Welcome to the Hashcracker - Made by r1me")
					keuze = input("Do you want to generate or brute force a hash ? (g / b ) : ")
				else:
					print("Exiting...")
					break
			
			else:

				wordlist = input("Wordlist: ")
						

				try:
					passFile = open(wordlist, "r", errors='ignore')
				except:
					print("No file found")
					quit()

				for word in passFile:

					enc_word = word.encode('utf-8')
					digest = hashlib.md5(enc_word.strip()).hexdigest()

					if digest == pass_hash:
						print(color1 + "Password found" + res)
						print("Password is --> " + word)
						flag = 1
						break

				if flag == 0:

					print(color2 + "Password is not in the list" + res)

				yesorno = input("Do you want to use Hashcracker again ? (y/n) : ")
				print()
				if (yesorno == "y"):
					print("Welcome to the Hashcracker - Made by r1me")
					keuze = input("Do you want to generate or brute force a hash ? (g / b ) : ")
				else:
					print("Exiting...")
					break


		elif (choice == "2"):
			flag = 0

			pass_hash = input("Enter SHA1 hash: ")
			
			rockyou = input("Do you want to use default wordlist [rockyou.txt] y/n : ")
			rockyou1 = "rockyou.txt"
			if (rockyou == "y"):
			
				try:
					passFile2 = open(rockyou1, "r", errors='ignore')
				except:
					print("No file found")
					quit()

				for word in passFile2:

					enc_word = word.encode('utf-8')
					digest = hashlib.sha1(enc_word.strip()).hexdigest()

					if digest == pass_hash:
						print(color1 + "Password found" + res)
						print("Password is --> " + word)
						flag = 1
						break
				if flag == 0:
					print(color2 + "Password is not in the list" + res)

				yesorno = input("Do you want to use Hashcracker again ? (y/n) : ")
				if (yesorno == "y"):
					print("Welcome to the Hashcracker - Made by r1me")
					keuze = input("Do you want to generate or brute force a hash ? (g / b ) : ")
				else:
					print("Exiting...")
					break
			else:
			
				wordlist = input("Wordlist: ")

				try:
					passFile2 = open(wordlist, "r", errors='ignore')
				except:
					print("No file found")
					quit()

				for word in passFile2:

					enc_word = word.encode('utf-8')
					digest = hashlib.sha1(enc_word.strip()).hexdigest()

					if digest == pass_hash:
						print(color1 + "Password found" + res)
						print("Password is --> " + word)
						flag = 1
						break
				if flag == 0:
					print(color2 + "Password is not in the list" + res)

				yesorno = input("Do you want to use Hashcracker again ? (y/n) : ")
				if (yesorno == "y"):
					print("Welcome to the Hashcracker - Made by r1me")
					keuze = input("Do you want to generate or brute force a hash ? (g / b ) : ")
				else:
					print("Exiting...")
					break

		elif (choice == "3"):
			flag = 0

			pass_hash = input("Enter SHA256 hash: ")
			
			rockyou = input("Do you want to use default wordlist [rockyou.txt] y/n : ")
			rockyou1 = "rockyou.txt"
			if (rockyou == "y"):
			
				try:
					passFile3 = open(rockyou1, "r", errors='ignore')
				except:
					print("No file found")
					quit()

				for word in passFile3:

					enc_word = word.encode('utf-8')
					digest = hashlib.sha256(enc_word.strip()).hexdigest()

					if digest == pass_hash:
						print(color1 + "Password found" + res)
						print("Password is --> " + word)
						flag = 1
						break
				if flag == 0:
					print(color2 + "Password is not in the list" + res)

				yesorno = input("Do you want to use Hashcracker again ? (y/n) : ")
				if (yesorno == "y"):
					print("Welcome to the Hashcracker - Made by r1me")
					keuze = input("Do you want to generate or brute force a hash ? (g / b ) : ")
				else:
					print("Exiting...")
					break
			else:


				wordlist = input("Wordlist: ")

				try:
					passFile3 = open(wordlist, "r", errors='ignore')
				except:
					print("No file found")
					quit()

				for word in passFile3:

					enc_word = word.encode('utf-8')
					digest = hashlib.sha256(enc_word.strip()).hexdigest()

					if digest == pass_hash:
						print(color1 + "Password found" + res)
						print("Password is --> " + word)
						flag = 1
						break
				if flag == 0:
					print(color2 + "Password is not in the list" + res)

				yesorno = input("Do you want to use Hashcracker again ? (y/n) : ")
				if (yesorno == "y"):
					print("Welcome to the Hashcracker - Made by r1me")
					keuze = input("Do you want to generate or brute force a hash ? (g / b ) : ")
				else:
					print("Exiting...")
					break

		elif (choice == "0"):
			print("Exiting...")
			break
	
else:
	print("Faulse input, please restart the program...")







