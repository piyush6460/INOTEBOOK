import React from "react";
import { Notes } from "./Notes";

export const Home = (props) => {
  const { toggleAlert } = props;
  return (
    <div>
      <Notes toggleAlert={toggleAlert} />
    </div>
  );
};
