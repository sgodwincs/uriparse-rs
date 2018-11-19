use std::hash::{Hash, Hasher};

fn get_percent_encoded_value(first_digit: Option<u8>, second_digit: Option<u8>) -> Result<u8, ()> {
    match (first_digit, second_digit) {
        (Some(first_digit), Some(second_digit)) => {
            let first_digit = hex_digit_to_decimal(first_digit)?;
            let second_digit = hex_digit_to_decimal(second_digit)?;
            Ok(first_digit * 16 + second_digit)
        }
        _ => Err(()),
    }
}

fn hex_digit_to_decimal(digit: u8) -> Result<u8, ()> {
    match digit {
        _ if digit >= b'A' && digit <= b'F' => Ok(digit - b'A' + 10),
        _ if digit >= b'a' && digit <= b'f' => Ok(digit - b'a' + 10),
        _ if digit.is_ascii_digit() => Ok(digit - b'0'),
        _ => Err(()),
    }
}

pub fn percent_encoded_hash<H>(value: &[u8], state: &mut H, case_sensitive: bool)
where
    H: Hasher,
{
    let mut bytes = value.iter();
    let mut length = 0;

    while let Some(byte) = bytes.next() {
        length += 1;

        match byte {
            b'%' => {
                let first_digit = bytes.next().cloned();
                let second_digit = bytes.next().cloned();
                let hex_value = get_percent_encoded_value(first_digit, second_digit).unwrap();
                hex_value.hash(state);
            }
            _ => if case_sensitive {
                byte.hash(state)
            } else {
                byte.to_ascii_lowercase().hash(state)
            },
        }
    }

    length.hash(state);
}

pub fn percent_encoded_equality(left: &[u8], right: &[u8], case_sensitive: bool) -> bool {
    let mut left_bytes = left.iter();
    let mut right_bytes = right.iter();

    loop {
        match (left_bytes.next(), right_bytes.next()) {
            (Some(b'%'), Some(b'%')) => (),
            (Some(b'%'), Some(&right_byte)) => {
                let first_digit = left_bytes.next().cloned();
                let second_digit = left_bytes.next().cloned();

                match get_percent_encoded_value(first_digit, second_digit) {
                    Ok(hex_value) if hex_value != right_byte => return false,
                    Err(_) => return false,
                    _ => (),
                }
            }
            (Some(&left_byte), Some(b'%')) => {
                let first_digit = right_bytes.next().cloned();
                let second_digit = right_bytes.next().cloned();

                match get_percent_encoded_value(first_digit, second_digit) {
                    Ok(hex_value) if hex_value != left_byte => return false,
                    Err(_) => return false,
                    _ => (),
                }
            }
            (Some(left_byte), Some(right_byte)) => {
                let equal = if case_sensitive {
                    left_byte == right_byte
                } else {
                    left_byte.eq_ignore_ascii_case(&right_byte)
                };

                if !equal {
                    return false;
                }
            }
            (None, None) => return true,
            _ => return false,
        }
    }
}
