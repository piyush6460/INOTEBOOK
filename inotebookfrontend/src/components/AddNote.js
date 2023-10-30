import React, { useContext, useState } from "react";
import NoteContext from "../context/notes/NoteContext";

export const AddNote = (props) => {
  const context = useContext(NoteContext);
  const { addNote } = context;

  const [note, setNote] = useState({
    title: "",
    description: "",
    tag: "",
  });
  const handleChange = (e) => {
    setNote({ ...note, [e.target.name]: e.target.value });
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    addNote(note.title, note.description, note.tag);
    setNote({ title: "", description: "", tag: "" });
    props.toggleAlert("Added Successfully", "success");
  };

  return (
    <div className="container my-auto">
      <h2>Add Notes</h2>
      <form action="">
        <div className="m-3">
          <label htmlFor="title" className="form-label">
            Title
          </label>
          <input
            type="text"
            className="form-control"
            id="title"
            name="title"
            value={note.title}
            onChange={handleChange}
            required
          />
          <div className="valid-feedback"></div>
          <div className="invalid-feedback"></div>
        </div>
        <div className="m-3">
          <label htmlFor="description" className="form-label">
            Description
          </label>
          <textarea
            className="form-control"
            id="description"
            name="description"
            rows="3"
            value={note.description}
            onChange={handleChange}
            required></textarea>
          <div className="valid-feedback"></div>
          <div className="invalid-feedback"></div>
        </div>
        <div className="m-3">
          <label htmlFor="tag" className="form-label">
            Tag
          </label>
          <input
            type="text"
            className="form-control"
            id="tag"
            name="tag"
            value={note.tag}
            onChange={handleChange}
          />
          <div className="valid-feedback"></div>
          <div className="invalid-feedback"></div>
        </div>
        <div className="m-3">
          <button
            disabled={note.title.length < 2 || note.description.length < 5}
            className="btn btn-outline-primary"
            onClick={handleSubmit}
            type="submit">
            Add Note
          </button>
        </div>
      </form>
    </div>
  );
};
