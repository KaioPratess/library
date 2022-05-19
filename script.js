const tBody = document.querySelector(".tbody");
const addBtn = document.querySelector(".add-btn");
const register = document.querySelector(".register-bg");
const closeBtn = document.querySelector(".close");
const saveBtn = document.querySelector(".btn");
const inputs = document.querySelectorAll("[data-key]");
const table = document.querySelector(".table-view");
const cards = document.querySelector(".card-view");
const tableSelector = document.querySelector(".select-table");
const cardSelector = document.querySelector(".select-card");

tableSelector.addEventListener('click', () => {
  table.classList.add("in-view");
  cards.classList.remove("in-view");
  tBody.innerHTML = '';
  displayTable();
});
cardSelector.addEventListener('click', () => {
  cards.classList.add("in-view");
  table.classList.remove("in-view");
  cards.innerHTML = '';
  displayCards();
})


let library = [];

  const libraryMethods = {
    addBook: function() {
      library.push(this)
    }
  }

function Book(title, author, pages, releaseYear, read, img) {
  this.title = title;
  this.author = author;
  this.pages = pages;
  this.releaseYear = releaseYear;
  this.read = read;
  this.img = img;
}

Book.prototype = Object.create(libraryMethods);

const theHobbit = new Book('The Hobbit', 'JJR Tolkien', '270', '1937', 'no', './img/book.jpg' );
const harryPotter = new Book('Harry Potter', 'JK Rowling', '400', '1999', 'no', './img/book.jpg');

theHobbit.addBook();
harryPotter.addBook();

function displayCards() {
    library.forEach((book) => {
      const card = document.createElement('div');
            card.classList.add('card');
            card.setAttribute('data-index', `${library.indexOf(book)}`);
      const imgBox = document.createElement('div');
      const img = document.createElement('img');
            img.setAttribute('alt', 'Book Image');
            img.setAttribute('width', '250');
            img.setAttribute('height', '340');
      const title = document.createElement('p');
      const author = document.createElement('p');
      const pages = document.createElement('p');
      const readL = document.createElement('label');
            readL.setAttribute('for', `read${library.indexOf(book)}`);
            readL.textContent = 'Read: ';
            readL.classList.add("read-label");
      const readI = document.createElement('input');
            readI.setAttribute('type', 'checkbox');
            readI.setAttribute('id', `read${library.indexOf(book)}`);
            readI.classList.add("read-input");
        if(book.read === "yes") {
          readI.setAttribute('checked', 'checked');
        }
            readI.addEventListener('change', () => {
              if(readI.checked) {
                book.read = "yes"
              } else {
                book.read = "no"
              }
              console.log(book)
            })
            readI.setAttribute('name', 'read');
      const bin = document.createElement('img');
            bin.setAttribute('src', './img/bin.png');
            bin.setAttribute('alt', 'bin');
            bin.classList.add('bin');
            bin.addEventListener('click', removeBook);
      imgBox.appendChild(img);
      card.appendChild(bin);
      card.appendChild(imgBox);
      card.appendChild(title);
      card.appendChild(author);
      card.appendChild(pages);
      for(key in book) {
        title.textContent = `${book.title}`;
        author.textContent = `Written by ${book.author}`;
        pages.textContent = `${book.pages} pages`;
        card.appendChild(readI);
        card.appendChild(readL);
        img.setAttribute('src',`${book.img}`);
      }
      cards.appendChild(card);
    })
}

function displayTable() {
    library.forEach((book) => {
      const row = document.createElement('tr');
            row.setAttribute('data-index', `${library.indexOf(book)}`);
      const removeBtn = document.createElement('img');
            removeBtn.setAttribute('src', './img/remove.png');
            removeBtn.setAttribute('alt', 'Remove Book');
            removeBtn.classList.add('remove-btn');
            removeBtn.addEventListener('click', removeBook);
      for(key in book) {
        if(book.hasOwnProperty(key)) {
          const value = book[key];
          const cell = document.createElement('td');
          cell.textContent = value;
          if(key === 'read') {
            const checkBox = document.createElement('input');
                  checkBox.setAttribute('type', 'checkbox');
                  checkBox.addEventListener('change', () => {
                    if(checkBox.checked) {
                      book.read = 'yes';
                    } else {
                      book.read = 'no';
                      checkBox.removeAttribute('checked');
                    }
                  })
            if(book.read === 'yes') {
              checkBox.setAttribute('checked','checked');
            }
            cell.textContent = '';
            cell.appendChild(checkBox);
            cell.appendChild(removeBtn);
          }
          if(key === 'img') {
            cell.style.display = 'none';
          }
          row.appendChild(cell);
        }
      }
      tBody.appendChild(row);
    });
}

function removeBook(event) {
  if(table.classList.contains('in-view')) {
    const row = event.path[2];
    row.remove();
    const index = row.getAttribute('data-index');
    library.splice(index, 1);
    tBody.innerHTML = '';
    displayTable();
  }
  else if(cards.classList.contains('in-view')) {
    const card = event.path[1];
    card.remove();
    const index = card.getAttribute('data-index');
    library.splice(index, 1);
    cards.innerHTML = '';
    displayCards();
  }
}

function saveBook() {
  tBody.innerHTML = '';
  cards.innerHTML = '';
  const array = [];
  inputs.forEach((input) => {
    array.push(input.value);
  });
  const newBook = new Book(...array);
  newBook.addBook();
  register.style.display = 'none';
  displayTable();
  displayCards();
}

function openRegister() {
  register.style.display = 'flex';
  inputs.forEach((input) => {
    input.value = '';
  })
}

function closeRegister() {
  register.style.display = 'none';
}

addBtn.addEventListener('click', openRegister);
closeBtn.addEventListener('click', closeRegister);
saveBtn.addEventListener('click', saveBook);

displayTable();
displayCards();