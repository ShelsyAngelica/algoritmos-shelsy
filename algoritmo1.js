/**
* Implementa un sistema de cache LRU (Least Recently Used) eficiente
* que mantenga un tamaño máximo y elimine elementos no usados recientemente
*
* @param {number} capacity - Capacidad máxima del cache
*/
class LRUCache {
    constructor(capacity) {
    // Tu implementación aquí
        this.capacity = capacity; //obtenemos que la capacidad es 3
        this.folder = []; // donde guardo 
        
    } 

    /**
    * Obtiene un valor del cache
    * @param {string} key - Clave a buscar
    * @returns {any} Valor encontrado o null
    */
    get(key) {
        // Tu implementación aquí
        let move = null;
        this.folder.forEach((element, index) => {
            if(element.key == key){
                move = this.folder.splice(index,1);   
                this.folder.push({key:move[0].key,value:move[0].value});
            }       
        });

        return move;               
    }

    /**
    * Almacena un valor en el cache
    * @param {string} key - Clave
    * @param {any} value - Valor a almacenar
    */
    put(key, value) {
        // Tu implementación aquí  
        if(this.folder.length < this.capacity){
            this.folder.push({key, value});
        }else{
            this.folder.splice(0,1)
            this.folder.push({key, value});
        }        
    }
}
// Ejemplo de uso:
const cache = new LRUCache(3);
cache.put("a", 1);
cache.put("b", 2);
cache.put("c", 3);

console.log(cache.get("a"));

cache.put("d", 4); // Elimina "b" (menos usado recientemente)


console.log(cache.folder);