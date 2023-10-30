const express = require("express");
const Note = require("../models/Note");
const router = express.Router();
const { body, validationResult } = require("express-validator");
const fetchuser = require("../middleware/fetchuser");

//ROUTE 1: Add a new note : POST "/api/note/addnote". Login Required.
router.post(
  "/addnote",
  fetchuser,
  [
    body("title", "Enter Title.").isLength({ min: 2 }),
    body(
      "description",
      "Description Must Contain Atleast 5 Characters."
    ).isLength({
      min: 5,
    }),
  ],
  async (req, res) => {
    try {
      const { title, description, tag } = req.body;
      //If there are errors, return Bad request and the errors
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }
      console.log(req.user);
      const note = new Note({
        title,
        description,
        tag,
        user: req.user,
      });
      const saveNote = await note.save();

      res.json(saveNote);
    } catch (error) {
      // console.error(error.message);
      res.status(300).send(error);
    }
  }
);

//ROUTE 2: Get all the note : GET "/api/note/fetchallnote". Login Required.
router.get("/fetchallnote", fetchuser, async (req, res) => {
  try {
    const note = await Note.find({ user: req.user });
    res.json(note);
  } catch (error) {
    console.error(error.message);
    res.status(500).send("Ineternal Server Error");
  }
});

//ROUTE 3: Update an existing note : PUT "/api/note/updatenote". Login Required
router.put("/updatenote/:id", fetchuser, async (req, res) => {
  const { title, description, tag } = req.body;
  //Create a newNote object
  const newNote = {};
  if (title) {
    newNote.title = title;
  }
  if (description) {
    newNote.description = description;
  }
  if (tag) {
    newNote.tag = tag;
  }
  try {
    // Find the note to be updated and update it.
    let note = await Note.findById(req.params.id);
    if (!note) {
      return res.status(404).send("Not Found");
    }
    //Allow update if user owns the note
    if (note.user.toString() !== req.user) {
      return res.status(401).send("Not Allowed");
    }
    note = await Note.findByIdAndUpdate(
      req.params.id,
      { $set: newNote },
      { new: true }
    );
    res.json({ note });
  } catch (error) {
    console.error(error.message);
    res.status(500).send("Ineternal Server Error");
  }
});

//ROUTE 4: Delete an existing note : DELETE "/api/note/deletenote". Login Required
router.delete("/deletenote/:id", fetchuser, async (req, res) => {
  try {
    // Find the note to be deleted and delete it.
    let note = await Note.findById(req.params.id);
    if (!note) {
      return res.status(404).send("Not Found");
    }
    //Allow delete if user owns the note
    if (note.user.toString() !== req.user) {
      return res.status(401).send("Not Allowed");
    }
    note = await Note.findByIdAndDelete(req.params.id);
    res.json({ note: note });
  } catch (error) {
    console.error(error.message);
    res.status(500).send("Ineternal Server Error");
  }
});
module.exports = router;
