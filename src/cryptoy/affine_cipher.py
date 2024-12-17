from math import (
    gcd,
)

from cryptoy.utils import (
    str_to_unicodes,
    unicodes_to_str,
)

# TP: Chiffrement affine


def compute_permutation(a: int, b: int, n: int) -> list[int]:
    # A implémenter, en sortie on doit avoir une liste result tel que result[i] == (a * i + b) % n
    return [(a * i + b) % n for i in range(n)]


def compute_inverse_permutation(a: int, b: int, n: int) -> list[int]:
    # A implémenter, pour cela on appelle perm = compute_permutation(a, b, n) et on calcule la permutation inverse
    # result qui est telle que: perm[i] == j implique result[j] == i
    perm = compute_permutation(a, b, n)
    inverse_perm = [0] * n
    for i, p in enumerate(perm):
        inverse_perm[p] = i
    return inverse_perm


def encrypt(msg: str, a: int, b: int) -> str:
    # A implémenter, en utilisant compute_permutation, str_to_unicodes et unicodes_to_str
    unicode_list = str_to_unicodes(msg)
    perm = compute_permutation(
        a, b, 0x110000
    )  # 0x110000 is the range of Unicode code points
    encrypted_unicode_list = [perm[code] for code in unicode_list]
    return unicodes_to_str(encrypted_unicode_list)


def encrypt_optimized(msg: str, a: int, b: int) -> str:
    # A implémenter, sans utiliser compute_permutation
    unicode_list = str_to_unicodes(msg)
    encrypted_unicode_list = [(a * code + b) % 0x110000 for code in unicode_list]
    return unicodes_to_str(encrypted_unicode_list)


def decrypt(msg: str, a: int, b: int) -> str:
    # A implémenter, en utilisant compute_inverse_permutation, str_to_unicodes et unicodes_to_str
    unicode_list = str_to_unicodes(msg)
    inv_perm = compute_inverse_permutation(a, b, 0x110000)
    decrypted_unicode_list = [inv_perm[code] for code in unicode_list]
    return unicodes_to_str(decrypted_unicode_list)


def decrypt_optimized(msg: str, a_inverse: int, b: int) -> str:
    # A implémenter, sans utiliser compute_inverse_permutation
    # On suppose que a_inverse a été précalculé en utilisant compute_affine_key_inverse, et passé
    # a la fonction
    unicode_list = str_to_unicodes(msg)
    decrypted_unicode_list = [
        (a_inverse * (code - b)) % 0x110000 for code in unicode_list
    ]
    return unicodes_to_str(decrypted_unicode_list)


def compute_affine_keys(n: int) -> list[int]:
    # A implémenter, doit calculer l'ensemble des nombre a entre 1 et n tel que gcd(a, n) == 1
    # c'est à dire les nombres premiers avec n
    return [a for a in range(1, n) if gcd(a, n) == 1]


def compute_affine_key_inverse(a: int, affine_keys: list, n: int) -> int:
    # Trouver a_1 dans affine_keys tel que a * a_1 % N == 1 et le renvoyer
    # Placer le code ici (une boucle)
    for a1 in affine_keys:
        if (a * a1) % n == 1:
            return a1

    # Si a_1 n'existe pas, alors a n'a pas d'inverse, on lance une erreur:
    raise RuntimeError(f"{a} has no inverse")


def attack() -> tuple[str, tuple[int, int]]:
    s = "࠾ੵΚઐ௯ஹઐૡΚૡೢఊஞ௯\u0c5bૡీੵΚ៚Κஞїᣍફ௯ஞૡΚր\u05ecՊՊΚஞૡΚՊեԯՊ؇ԯրՊրր"
    # trouver msg, a et b tel que affine_cipher_encrypt(msg, a, b) == s
    # avec comme info: "bombe" in msg et b == 58

    # Placer le code ici
    a = 1
    found = False
    while not found:
        decrypted = decrypt(s, a, 58)
        if "bombe" in decrypted:
            found = True
            return (decrypted, (a, 58))
        else:
            a += 1

    raise RuntimeError("Failed to attack")


def attack_optimized() -> tuple[str, tuple[int, int]]:
    s = (
        "જഏ൮ൈ\u0c51ܲ೩\u0c51൛൛అ౷\u0c51ܲഢൈᘝఫᘝా\u0c51\u0cfc൮ܲఅܲᘝ൮ᘝܲాᘝఫಊಝ"
        "\u0c64\u0c64ൈᘝࠖܲೖఅܲఘഏ೩ఘ\u0c51ܲ\u0c51൛൮ܲఅ\u0cfc\u0cfcඁೖᘝ\u0c51"
    )
    # trouver msg, a et b tel que affine_cipher_encrypt(msg, a, b) == s
    # avec comme info: "bombe" in msg

    # Placer le code ici
    possibilites = compute_affine_keys(0x110000)
    for a in range(1, len(possibilites)):
        try:
            a_inverse = compute_affine_key_inverse(a, possibilites, 0x110000)
        except RuntimeError:
            continue
        for b in range(1, 15000):
            msg = decrypt_optimized(s, a_inverse, b)
            if "bombe" in msg:
                return (msg, (a, b))

    raise RuntimeError("Failed to attack")