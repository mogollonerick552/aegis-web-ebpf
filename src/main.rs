use libbpf_rs::ObjectBuilder;
use std::time::Duration;

fn main() {
    println!("[🛡️] Aegis-Web: Iniciando carga del Virtual Patcher...");

    let mut obj = ObjectBuilder::default()
        .open_file("aegis_web.o") 
        .expect("Error abriendo aegis_web.o")
        .load()
        .expect("Error cargando el eBPF en el Kernel");

    let prog = obj
        .prog_mut("block_web_rce")
        .expect("No se encontró el programa block_web_rce");
    
    let _link = prog.attach().expect("Error al adjuntar LSM");

    println!("[+] Escudo activo: Bloqueando RCEs en servidores web.");
    println!("[!] Presiona Ctrl+C para detener.");

    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}
