from cryptoy.utils import (
    str_to_unicodes,
    unicodes_to_str,
)

# TP: Chiffrement de César


def encrypt(msg: str, shift: int) -> str:
    # Implémenter le chiffrement de César
    # Il faut utiliser la fonction str_to_unicodes, puis appliquer la formule
    # (x + shift) % 0x110000 pour chaque unicode du tableau puis utiliser
    # unicodes_to_str pour repasser en string
    unicode_list = str_to_unicodes(msg)
    shifted_unicode_list = [(code + shift) % 0x110000 for code in unicode_list]
    return unicodes_to_str(shifted_unicode_list)


def decrypt(msg: str, shift: int) -> str:
    # Implémenter le déchiffrement. Astuce: on peut implémenter le déchiffrement en
    # appelant la fonction de chiffrement en modifiant légèrement le paramètre
    return encrypt(msg, -shift)


def attack() -> tuple[str, int]:
    s = "恱恪恸急恪恳恳恪恲恮恸急恦恹恹恦恶恺恪恷恴恳恸急恵恦恷急恱恪急恳恴恷恩怱急恲恮恳恪恿急恱恦急恿恴恳恪"
    # Il faut déchiffrer le message s en utilisant l'information:
    # 'ennemis' apparait dans le message non chiffré

    # Code a placer ici, il faut return un couple (msg, shift)
    # ou msg est le message déchiffré, et shift la clef de chiffrage correspondant

    for shift in range(0x110000):
        decrypted_message = decrypt(s, shift)
        if "ennemis" in decrypted_message:
            return decrypted_message, shift

    # Si on ne trouve pas on lance une exception:
    raise RuntimeError("Failed to attack")
