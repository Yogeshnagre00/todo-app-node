let skip = 0;

window.onload = genrateTodos();

function genrateTodos() {
  axios
    .get(`/read-item?skip=${skip}`)
    .then((res) => {
      if (res.data.status !== 200) {
        alert(res.data.message);
        return;
      }
      const todos = res.data.data;

      document.getElementById("item_list").insertAdjacentHTML(
        "beforeend",
        todos
          .map((item) => {
            return `<li class="list-group-item list-group-item-action d-flex align-items-center justify-content-between">
        <span class="item-text"> ${item.todo}</span>
        <div>
        <button data-id="${item._id}" class="edit-me btn btn-secondary btn-sm mr-1">Edit</button>
        <button data-id="${item._id}" class="delete-me btn btn-danger btn-sm">Delete</button>
        </div></li>`;
          })
          .join("")
      );

      skip += todos.length;

      return;
    })
    .catch((err) => {
      console.log(err);
      alert(err.message);
      return;
    });
}

document.addEventListener("click", function (event) {
  //edit
  if (event.target.classList.contains("edit-me")) {
    const newData = prompt("Enter new Todo Text");
    const id = event.target.getAttribute("data-id");

    axios
      .post("/edit-item", { id, newData })
      .then((res) => {
        if (res.data.status !== 200) {
          alert(res.data.message);
          return;
        }

        event.target.parentElement.parentElement.querySelector(
          ".item-text"
        ).innerHTML = newData;
      })
      .catch((err) => {
        console.log(err);
      });
  }
  //delete
  else if (event.target.classList.contains("delete-me")) {
    const id = event.target.getAttribute("data-id");

    axios
      .post("/delete-item", { id })
      .then((res) => {
        if (res.data.status !== 200) {
          alert(res.data.message);
          return;
        }
        event.target.parentElement.parentElement.remove();
        return;
      })
      .catch((err) => {
        console.log(err);
      });
  }
  //add
  else if (event.target.classList.contains("add_item")) {
    const todo = document.getElementById("create_field").value;

    axios
      .post("/create-item", { todo })
      .then((res) => {
        if (res.data.status !== 201) {
          alert(res.data.message);
        }
        document.getElementById("create_field").value = "";

        document.getElementById("item_list").insertAdjacentHTML(
          "beforeend",
          `<li class="list-group-item list-group-item-action d-flex align-items-center justify-content-between">
                <span class="item-text"> ${res.data.data.todo}</span>
                <div>
                <button data-id="${res.data.data._id}" class="edit-me btn btn-secondary btn-sm mr-1">Edit</button>
                <button data-id="${res.data.data._id}" class="delete-me btn btn-danger btn-sm">Delete</button>
                </div></li>`
        );
      })
      .catch((err) => {
        console.log(err);
      });
  }
  //show more
  else if (event.target.classList.contains("show_more")) {
    genrateTodos();
  }
});
