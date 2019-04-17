package vn.edu.leading.uaa.services;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import vn.edu.leading.uaa.models.RoleModel;
import vn.edu.leading.uaa.models.UserModel;
import vn.edu.leading.uaa.repositories.RoleRepository;
import vn.edu.leading.uaa.repositories.UserRepository;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
public class UserServicelmpl implements UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;


    public UserServicelmpl(UserRepository userRepository, RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }

    @Override
    public List<UserModel> findAll() {
        return userRepository.findAll();
    }

    @Override
    public List<UserModel> search(String term) {
        return userRepository.findAllByUsernameContaining
                (term);
    }

    @Override
    public UserModel findById(Long id) {
        return userRepository.findById(id).get();
    }

    @Override
    public boolean update(UserModel userModel) {
        UserModel userModel1 = userRepository.findById(userModel.getId()).orElse(null);
        if (userModel == null)
            return false;
        userRepository.save(userModel);
        return true;
    }

    @Override
    public void save(UserModel userModel) {
        userRepository.save(userModel);
    }

    @Override
    public boolean delete(Long id) {
        UserModel userModel = userRepository.findById(id).orElse(null);
        if (userModel == null)
            return false;
        userRepository.delete(userModel);
        return true;
    }

    @Override
    @Transactional
    public void register(UserModel userModel) throws Exception {
        if (userRepository.findByUsername(userModel.getUsername()).isPresent()){

            throw new Exception("user_exits");
        }

//        if (userRepository.findByEmail (userModel.getMail()).isPresent())
//        {
//            throw new Exception("user_exits");
//        }

        RoleModel roleModel = roleRepository.findByName("ROLE_USER");
        Set<RoleModel> roleModels = new HashSet<>();
        roleModels.add(roleModel);
        userModel.setRoleModels(roleModels);
        //userModel.setPassword(passwordEncoder.encode(userModel.getPassword()));
        userRepository.save(userModel);
    }
}
