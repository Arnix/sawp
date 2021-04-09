extern crate sawp_ffi_derive;
pub use sawp_ffi_derive::GenerateFFI;

#[macro_export]
macro_rules! nullcheck {
    ( $($ptr:expr),*) => {
        $(
        if $ptr.is_null() {
            panic!("{} is NULL in {}", stringify!($ptr), line!());
        }
        )*
    }
}

#[macro_export]
macro_rules! deref {
    ( $($ptr:expr),*) => {
        $(
        {
            $crate::nullcheck!($ptr);
            &*$ptr
        }
        )*
    }
}

#[macro_export]
macro_rules! deref_mut {
    ( $($ptr:expr),*) => {
        $(
        {
            $crate::nullcheck!($ptr);
            &mut *$ptr
        }
        )*
    }
}

pub trait IntoFFIPtr<T> {
    fn into_ffi_ptr(self) -> *mut T;
}

impl<'a, T> IntoFFIPtr<T> for Option<T> {
    fn into_ffi_ptr(self) -> *mut T {
        match self {
            Some(value) => value.into_ffi_ptr(),
            None => std::ptr::null_mut(),
        }
    }
}

impl<T> IntoFFIPtr<T> for T {
    fn into_ffi_ptr(self) -> *mut T {
        let boxed = Box::new(self);
        Box::into_raw(boxed)
    }
}

#[cfg(test)]
extern crate sawp_flags;

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;
    use sawp_flags::{BitFlags, Flag, Flags};

    #[test]
    #[should_panic]
    fn test_deref() {
        let ptr: *const u8 = std::ptr::null();
        unsafe {
            ::deref!(ptr);
        }
    }

    #[test]
    #[should_panic]
    fn test_nullcheck() {
        let ptr: *const u8 = std::ptr::null();
        nullcheck!(ptr);
    }

    #[test]
    #[should_panic]
    fn test_derive_nullcheck() {
        #[derive(GenerateFFI)]
        pub struct MyStruct {
            pub field: u8,
        }

        unsafe {
            my_struct_get_field(std::ptr::null());
        }
    }

    #[test]
    fn test_struct() {
        #[repr(u16)]
        #[derive(Debug, PartialEq, Copy, Clone)]
        pub enum Version {
            Version1 = 0x0100,
            Version1_1 = 0x0101,
            Version2 = 0x0200,
        }

        #[repr(u8)]
        #[derive(Debug, Clone, Copy, PartialEq, BitFlags)]
        pub enum FileType {
            Read = 0b0000_0001,
            Write = 0b0000_0010,
        }

        #[derive(GenerateFFI)]
        #[sawp_ffi(prefix = "sawp")]
        pub struct MyStruct {
            pub num: usize,
            #[sawp_ffi(copy)]
            pub version: Version,
            #[sawp_ffi(flag = "u8")]
            pub file_type: Flags<FileType>,
            private: usize,
            #[sawp_ffi(skip)]
            pub skipped: usize,
            pub complex: Vec<u8>,
            pub string: String,
            pub option: Option<u8>,
        }

        let my_struct = MyStruct {
            num: 12,
            version: Version::Version1,
            file_type: FileType::Write.into(),
            private: 0,
            skipped: 128,
            complex: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            string: String::from("test"),
            option: Some(41),
        };
        unsafe {
            assert_eq!(sawp_my_struct_get_num(&my_struct), 12);
            assert_eq!(sawp_my_struct_get_version(&my_struct), Version::Version1);
            assert_eq!(sawp_my_struct_get_file_type(&my_struct), 0b0000_0010);
            assert_ne!(sawp_my_struct_get_complex(&my_struct), std::ptr::null());
            assert_eq!((*sawp_my_struct_get_complex(&my_struct)).len(), 10);
            assert_ne!(sawp_my_struct_get_complex_ptr(&my_struct), std::ptr::null());
            assert_eq!(sawp_my_struct_get_complex_len(&my_struct), 10);
            assert_ne!(sawp_my_struct_get_string(&my_struct), std::ptr::null());
            assert_ne!(sawp_my_struct_get_string_ptr(&my_struct), std::ptr::null());
            assert_eq!(sawp_my_struct_get_string_len(&my_struct), 4);

            assert_ne!(sawp_my_struct_get_option(&my_struct), std::ptr::null());
            assert_eq!(*sawp_my_struct_get_option(&my_struct), 41);
        }
    }

    #[test]
    fn test_enum() {
        #[repr(u16)]
        #[derive(Copy, Clone)]
        pub enum Version {
            Version1 = 0x0100,
            Version1_1 = 0x0101,
            Version2 = 0x0200,
        }

        #[repr(u8)]
        #[derive(Debug, Clone, Copy, PartialEq, BitFlags)]
        pub enum FileType {
            Read = 0b0000_0001,
            Write = 0b0000_0010,
        }

        #[derive(GenerateFFI)]
        pub enum MyEnum {
            UnnamedSingle(u8),
            UnnamedMultiple(String, Vec<u8>),
            Named {
                a: u8,
                b: Vec<u8>,
                c: String,
                d: Option<u8>,
                #[sawp_ffi(flag = "u8")]
                file_type: Flags<FileType>,
            },
            Empty,
        }

        let single = MyEnum::UnnamedSingle(12);
        let multiple = MyEnum::UnnamedMultiple(String::from("test"), vec![34]);
        let named = MyEnum::Named {
            a: 2,
            b: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            c: String::from("test"),
            d: Some(41),
            file_type: FileType::Write.into(),
        };
        let empty = MyEnum::Empty;

        unsafe {
            assert_eq!(my_enum_get_type(&single), MyEnumType::UnnamedSingle);
            assert_eq!(my_enum_get_type(&multiple), MyEnumType::UnnamedMultiple);
            assert_eq!(my_enum_get_type(&named), MyEnumType::Named);
            assert_eq!(my_enum_get_type(&empty), MyEnumType::Empty);

            assert_ne!(my_enum_get_unnamed_single(&single), std::ptr::null());
            assert_eq!(*my_enum_get_unnamed_single(&single), 12);

            assert_ne!(my_enum_get_unnamed_multiple_0(&multiple), std::ptr::null());
            assert_eq!(
                *my_enum_get_unnamed_multiple_0(&multiple),
                String::from("test")
            );
            assert_eq!(my_enum_get_unnamed_multiple_0_len(&multiple), 4);
            assert_ne!(my_enum_get_unnamed_multiple_1(&multiple), std::ptr::null());
            assert_eq!(*my_enum_get_unnamed_multiple_1(&multiple), vec![34]);
            assert_eq!(my_enum_get_unnamed_multiple_1_len(&multiple), 1);

            assert_ne!(my_enum_get_named_a(&named), std::ptr::null());
            assert_eq!(*my_enum_get_named_a(&named), 2);
            assert_ne!(my_enum_get_named_b(&named), std::ptr::null());
            assert_eq!((*my_enum_get_named_b(&named)).len(), 10);
            assert_ne!(my_enum_get_named_b_ptr(&named), std::ptr::null());
            assert_eq!(my_enum_get_named_b_len(&named), 10);

            assert_ne!(my_enum_get_named_c(&named), std::ptr::null());
            assert_ne!(my_enum_get_named_c_ptr(&named), std::ptr::null());
            assert_eq!(my_enum_get_named_c_len(&named), 4);

            assert_ne!(my_enum_get_named_d(&named), std::ptr::null());
            assert_eq!(*my_enum_get_named_d(&named), 41);

            assert_ne!(my_enum_get_named_file_type(&named), std::ptr::null());
            assert_eq!(*my_enum_get_named_file_type(&named), 0b0000_0010);

            assert_eq!(my_enum_get_unnamed_single(&multiple), std::ptr::null());
        }
    }

    #[test]
    fn test_into_ffi_ptr() {
        let option: Option<u8> = Some(41);
        let null_option: Option<u8> = None;
        let non_option = 42;

        let option_ffi: *mut u8 = option.into_ffi_ptr();
        let null_option_ffi: *mut u8 = null_option.into_ffi_ptr();
        let non_option_ffi: *mut u8 = non_option.into_ffi_ptr();

        unsafe {
            assert_ne!(option_ffi, std::ptr::null_mut());
            assert_eq!(*option_ffi, 41);
            assert_eq!(null_option_ffi, std::ptr::null_mut());
            assert_ne!(non_option_ffi, std::ptr::null_mut());
            assert_eq!(*non_option_ffi, 42);

            Box::from_raw(option_ffi);
            Box::from_raw(non_option_ffi);
        }
    }
}
