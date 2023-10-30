import React, { useContext } from "react";
import NoteContext from "../context/notes/NoteContext";

export const Noteitem = (props) => {
  const context = useContext(NoteContext);
  const { removeNote } = context;
  const { note, updateNote } = props;
  return (
    <div className="col-md-3">
      <div className="card m-2">
        <div className="card-body">
          <h4 className="card-title">{note.title}</h4>
          <p className="card-text">{note.description} </p>
          <h6 className="card-link">{note.tag}</h6>
          <div className="row">
            <button
              className="col btn btn-outline-success m-2"
              onClick={() => {
                updateNote(note);
              }}>
              Edit
            </button>
            <button
              className="col btn btn-outline-danger m-2"
              onClick={() => {
                removeNote(note._id);
                props.toggleAlert("Deleted Successfully", "success");
              }}>
              Remove
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
