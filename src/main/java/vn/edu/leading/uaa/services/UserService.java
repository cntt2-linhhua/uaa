package vn.edu.leading.uaa.services;

import vn.edu.leading.uaa.models.UserModel;

import java.util.List;

public interface UserService {

    List<UserModel> findAll();


    UserModel findById(Long id);

    boolean update(UserModel userModel);

    void save(UserModel userModel);

    boolean delete(Long id);

    //void register(UserModel userModel) throws Exception;
}
