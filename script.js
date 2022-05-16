let library = [];

const libraryMethods = {
  addBook: function() {
    library.push(this)
  },
  removeBook: function() {
    library.pop(this);
  }
}

function Book(title, author, pages, releaseYear, read) {
  this.title = title;
  this.author = author;
  this.pages = pages;
  this.releaseYear = releaseYear;
  this.read = read;
}

Book.prototype = Object.create(libraryMethods);

const theHobbit = new Book('The Hobbit', 'JJR Tolkien', '270', '1937', 'read');
const theLordOfTheRings = new Book('The Lord of The Rings','JJR Tolkien', '400', '1940', 'not read');

theHobbit.addBook();
theLordOfTheRings.addBook();

console.log(library)